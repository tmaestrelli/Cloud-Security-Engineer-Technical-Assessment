package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	compute "cloud.google.com/go/compute/apiv1"
	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"google.golang.org/api/iterator"
)

type InsecureRule struct {
	Protocol string `json:"protocol"`
	Port     string `json:"port"`
	Source   string `json:"source"`
}

type AWSSecurityGroupFinding struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Region        string         `json:"region"`
	InsecureRules []InsecureRule `json:"insecure_rules"`
}

type GCPFirewallFinding struct {
	Name          string         `json:"name"`
	Network       string         `json:"network"`
	InsecureRules []InsecureRule `json:"insecure_rules"`
}

type AzureNSGFinding struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	InsecureRules []InsecureRule `json:"insecure_rules"`
}

type Report struct {
	AWS struct {
		SecurityGroups []AWSSecurityGroupFinding `json:"security_groups"`
	} `json:"aws"`

	GCP struct {
		FirewallRules []GCPFirewallFinding `json:"firewall_rules"`
	} `json:"gcp"`

	Azure struct {
		NSGs []AzureNSGFinding `json:"nsgs"`
	} `json:"azure"`

	Errors []string `json:"errors,omitempty"`
}

func main() {
	awsRegions := flag.String("aws-regions", "", "Comma-separated AWS regions to scan, for example: us-east-1,us-west-2")
	gcpProject := flag.String("gcp-project", "", "GCP project ID to scan")
	azureSubscriptionID := flag.String("azure-subscription-id", "", "Azure subscription ID to scan")
	flag.Parse()

	if *awsRegions == "" && *gcpProject == "" && *azureSubscriptionID == "" {
		fmt.Fprintln(os.Stderr, "No cloud target provided.")
		fmt.Fprintln(os.Stderr, "Provide at least one of: --aws-regions, --gcp-project, --azure-subscription-id")
		os.Exit(1)
	}

	ctx := context.Background()
	report := Report{}

	report.AWS.SecurityGroups = []AWSSecurityGroupFinding{}
	report.GCP.FirewallRules = []GCPFirewallFinding{}
	report.Azure.NSGs = []AzureNSGFinding{}

	if *awsRegions != "" {
		for _, region := range splitCSV(*awsRegions) {
			findings, err := scanAWS(ctx, region)
			if err != nil {
				report.Errors = append(report.Errors, fmt.Sprintf("aws/%s: %v", region, err))
				continue
			}

			report.AWS.SecurityGroups = append(report.AWS.SecurityGroups, findings...)
		}
	}

	if *gcpProject != "" {
		findings, err := scanGCP(ctx, *gcpProject)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("gcp/%s: %v", *gcpProject, err))
		} else {
			report.GCP.FirewallRules = findings
		}
	}

	if *azureSubscriptionID != "" {
		findings, err := scanAzure(ctx, *azureSubscriptionID)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("azure/%s: %v", *azureSubscriptionID, err))
		} else {
			report.Azure.NSGs = findings
		}
	}

	output, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create JSON output: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(output))

	if len(report.Errors) > 0 {
		os.Exit(1)
	}
}

func scanAWS(ctx context.Context, region string) ([]AWSSecurityGroupFinding, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, err
	}

	client := ec2.NewFromConfig(cfg)

	paginator := ec2.NewDescribeSecurityGroupsPaginator(
		client,
		&ec2.DescribeSecurityGroupsInput{},
	)

	findings := []AWSSecurityGroupFinding{}

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, securityGroup := range page.SecurityGroups {
			insecureRules := []InsecureRule{}

			for _, permission := range securityGroup.IpPermissions {
				protocol := aws.ToString(permission.IpProtocol)
				port := awsPort(permission.FromPort, permission.ToPort)

				if protocol == "-1" {
					protocol = "*"
				}

				// Security logic:
				// AWS Security Group ingress rules expose IPv4 sources through IpRanges.
				// Any ingress rule containing CidrIp 0.0.0.0/0 is considered internet-facing.
				for _, ipRange := range permission.IpRanges {
					if aws.ToString(ipRange.CidrIp) == "0.0.0.0/0" {
						insecureRules = append(insecureRules, InsecureRule{
							Protocol: protocol,
							Port:     port,
							Source:   "0.0.0.0/0",
						})
					}
				}
			}

			if len(insecureRules) > 0 {
				findings = append(findings, AWSSecurityGroupFinding{
					ID:            aws.ToString(securityGroup.GroupId),
					Name:          aws.ToString(securityGroup.GroupName),
					Region:        region,
					InsecureRules: insecureRules,
				})
			}
		}
	}

	return findings, nil
}

func scanGCP(ctx context.Context, projectID string) ([]GCPFirewallFinding, error) {
	client, err := compute.NewFirewallsRESTClient(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	request := &computepb.ListFirewallsRequest{
		Project: projectID,
	}

	firewalls := client.List(ctx, request)
	findings := []GCPFirewallFinding{}

	for {
		rule, err := firewalls.Next()
		if err == iterator.Done {
			break
		}

		if err != nil {
			return nil, err
		}

		if strings.ToUpper(rule.GetDirection()) != "INGRESS" {
			continue
		}

		sourceRanges := rule.GetSourceRanges()

		// Security logic:
		// The assessment asks for sourceRanges containing 0.0.0.0/0.
		// Empty source ranges are also treated as open for conservative review,
		// because firewall rules without explicit source constraints should not
		// be ignored in a security scanner.
		if len(sourceRanges) == 0 {
			sourceRanges = []string{"0.0.0.0/0"}
		}

		if !contains(sourceRanges, "0.0.0.0/0") {
			continue
		}

		insecureRules := []InsecureRule{}

		for _, allowed := range rule.GetAllowed() {
			protocol := allowed.GetIPProtocol()
			ports := allowed.GetPorts()

			if protocol == "" {
				protocol = "*"
			}

			if len(ports) == 0 {
				ports = []string{"all"}
			}

			for _, port := range ports {
				insecureRules = append(insecureRules, InsecureRule{
					Protocol: protocol,
					Port:     port,
					Source:   "0.0.0.0/0",
				})
			}
		}

		if len(insecureRules) > 0 {
			findings = append(findings, GCPFirewallFinding{
				Name:          rule.GetName(),
				Network:       rule.GetNetwork(),
				InsecureRules: insecureRules,
			})
		}
	}

	return findings, nil
}

func scanAzure(ctx context.Context, subscriptionID string) ([]AzureNSGFinding, error) {
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}

	client, err := armnetwork.NewSecurityGroupsClient(subscriptionID, credential, nil)
	if err != nil {
		return nil, err
	}

	pager := client.NewListAllPager(nil)
	findings := []AzureNSGFinding{}

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, nsg := range page.Value {
			if nsg == nil || nsg.Properties == nil {
				continue
			}

			insecureRules := []InsecureRule{}

			for _, rule := range nsg.Properties.SecurityRules {
				if rule == nil || rule.Properties == nil {
					continue
				}

				properties := rule.Properties

				if enumToString(properties.Direction) != "Inbound" {
					continue
				}

				if enumToString(properties.Access) != "Allow" {
					continue
				}

				protocol := enumToString(properties.Protocol)
				if protocol == "" {
					protocol = "*"
				}

				ports := azureDestinationPorts(properties)
				sources := azureSources(properties)

				// Security logic:
				// Azure NSGs may represent internet exposure as 0.0.0.0/0,
				// *, Any, or Internet. These are normalized in the JSON output.
				for _, source := range sources {
					if !isOpenAzureSource(source) {
						continue
					}

					for _, port := range ports {
						insecureRules = append(insecureRules, InsecureRule{
							Protocol: protocol,
							Port:     port,
							Source:   normalizeSource(source),
						})
					}
				}
			}

			if len(insecureRules) > 0 {
				findings = append(findings, AzureNSGFinding{
					ID:            stringValue(nsg.ID),
					Name:          stringValue(nsg.Name),
					InsecureRules: insecureRules,
				})
			}
		}
	}

	return findings, nil
}

func awsPort(fromPort *int32, toPort *int32) string {
	if fromPort == nil && toPort == nil {
		return "*"
	}

	if fromPort != nil && toPort != nil {
		if *fromPort == *toPort {
			return fmt.Sprintf("%d", *fromPort)
		}

		return fmt.Sprintf("%d-%d", *fromPort, *toPort)
	}

	if fromPort != nil {
		return fmt.Sprintf("%d", *fromPort)
	}

	return fmt.Sprintf("%d", *toPort)
}

func azureSources(properties *armnetwork.SecurityRulePropertiesFormat) []string {
	sources := []string{}

	if properties.SourceAddressPrefix != nil {
		sources = append(sources, stringValue(properties.SourceAddressPrefix))
	}

	for _, source := range properties.SourceAddressPrefixes {
		if source != nil {
			sources = append(sources, stringValue(source))
		}
	}

	return sources
}

func azureDestinationPorts(properties *armnetwork.SecurityRulePropertiesFormat) []string {
	ports := []string{}

	if properties.DestinationPortRange != nil {
		ports = append(ports, stringValue(properties.DestinationPortRange))
	}

	for _, port := range properties.DestinationPortRanges {
		if port != nil {
			ports = append(ports, stringValue(port))
		}
	}

	if len(ports) == 0 {
		ports = append(ports, "*")
	}

	return ports
}

func isOpenAzureSource(source string) bool {
	normalized := strings.ToLower(strings.TrimSpace(source))

	return normalized == "0.0.0.0/0" ||
		normalized == "*" ||
		normalized == "any" ||
		normalized == "internet"
}

func normalizeSource(source string) string {
	normalized := strings.ToLower(strings.TrimSpace(source))

	if normalized == "*" || normalized == "any" || normalized == "internet" {
		return "0.0.0.0/0"
	}

	return source
}

func splitCSV(value string) []string {
	items := strings.Split(value, ",")
	result := []string{}

	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}

	return false
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}

	return *value
}

func enumToString[T ~string](value *T) string {
	if value == nil {
		return ""
	}

	return string(*value)
}
