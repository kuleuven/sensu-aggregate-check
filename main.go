package main

import (
	"bytes"
    "crypto/tls"
    "crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
    "strings"

	"github.com/sensu/sensu-go/types"
	"github.com/spf13/cobra"
)

var (
	checkLabels  string
	entityLabels string
	namespaces   string
    apiProto     string
	apiHost      string
	apiPort      string
	apiUser      string
	apiPass      string
    caPath       string
	warnPercent  int
	critPercent  int
	warnCount    int
	critCount    int
)

type Auth struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"`
}

type Counters struct {
	Entities int
	Checks   int
	Ok       int
	Warning  int
	Critical int
	Unknown  int
	Total    int
}

func main() {
	rootCmd := configureRootCommand()
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func configureRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sensu-aggregate-check",
		Short: "The Sensu Go Event Aggregates Check plugin",
		RunE:  run,
	}

	cmd.Flags().StringVarP(&checkLabels,
		"check-labels",
		"l",
		"",
		"Sensu Go Event Check Labels to filter by (e.g. 'aggregate=foo')")

	cmd.Flags().StringVarP(&entityLabels,
		"entity-labels",
		"e",
		"",
		"Sensu Go Event Entity Labels to filter by (e.g. 'aggregate=foo,app=bar')")

	cmd.Flags().StringVarP(&namespaces,
		"namespaces",
		"n",
		"default",
		"Comma-delimited list of Sensu Go Namespaces to query for Events (e.g. 'us-east-1,us-west-2')")

    cmd.Flags().StringVarP(&apiProto,
        "api-proto",
        "",
        "http",
        "Sensu Go Backend API Protocol (e.g. 'https')")

	cmd.Flags().StringVarP(&apiHost,
		"api-host",
		"H",
		"127.0.0.1",
		"Sensu Go Backend API Host (e.g. 'sensu-backend.example.com')")

	cmd.Flags().StringVarP(&apiPort,
		"api-port",
		"p",
		"8080",
		"Sensu Go Backend API Port (e.g. 4242)")

	cmd.Flags().StringVarP(&apiUser,
		"api-user",
		"u",
		"admin",
		"Sensu Go Backend API User")

	cmd.Flags().StringVarP(&apiPass,
		"api-pass",
		"P",
		"P@ssw0rd!",
		"Sensu Go Backend API User")

    cmd.Flags().StringVarP(&caPath,
        "ca-path",
        "",
        "",
        "Path to CA certificate")

	cmd.Flags().IntVarP(&warnPercent,
		"warn-percent",
		"w",
		0,
		"Warning threshold - % of Events in warning state")

	cmd.Flags().IntVarP(&critPercent,
		"crit-percent",
		"c",
		0,
		"Critical threshold - % of Events in critical state")

	cmd.Flags().IntVarP(&warnCount,
		"warn-count",
		"W",
		0,
		"Warning threshold - count of Events in warning state")

	cmd.Flags().IntVarP(&critCount,
		"crit-count",
		"C",
		0,
		"Critical threshold - count of Events in critical state")

	_ = cmd.MarkFlagRequired("check-labels")

	return cmd
}

func run(cmd *cobra.Command, args []string) error {
	if len(args) != 0 {
		_ = cmd.Help()
		return fmt.Errorf("invalid argument(s) received")
	}

    if caPath != "" {
        err := initCa(caPath)
        if err != nil {
            return err
        }
    }

	return evalAggregate()
}

func initCa(caPath string) error {
   certs := x509.NewCertPool()
   pemData, err := ioutil.ReadFile(caPath)
    if err != nil {
       return err
   }
   certs.AppendCertsFromPEM(pemData)

   newTlsConfig := &tls.Config{}
   newTlsConfig.RootCAs = certs

   defaultTransport := http.DefaultTransport.(*http.Transport)
   defaultTransport.TLSClientConfig = newTlsConfig
   return nil
}

func authenticate() (Auth, error) {
	var auth Auth
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s://%s:%s/auth", apiProto, apiHost, apiPort),
		nil,
	)
	if err != nil {
		return auth, err
	}

	req.SetBasicAuth(apiUser, apiPass)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return auth, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return auth, err
	}

	err = json.NewDecoder(bytes.NewReader(body)).Decode(&auth)

	return auth, err
}

func parseLabelArg(labelArg string) map[string]string {
	labels := map[string]string{}

	pairs := strings.Split(labelArg, ",")

	for _, pair := range pairs {
		parts := strings.Split(pair, "=")
		if len(parts) == 2 {
			labels[parts[0]] = parts[1]
		}
	}

	return labels
}

func filterEvents(events []*types.Event) []*types.Event {
	result := []*types.Event{}

	cLabels := parseLabelArg(checkLabels)
	eLabels := parseLabelArg(entityLabels)

	for _, event := range events {
		selected := true

		for key, value := range cLabels {
			if event.Check.ObjectMeta.Labels[key] != value {
				selected = false
				break
			}
		}

		if selected {
			for key, value := range eLabels {
				if event.Entity.ObjectMeta.Labels[key] != value {
					selected = false
					break
				}
			}
		}

		if selected {
			result = append(result, event)
		}
	}

	return result
}

func getEvents(auth Auth, namespace string) ([]*types.Event, error) {
	url := fmt.Sprintf("%s://%s:%s/api/core/v2/namespaces/%s/events", apiProto, apiHost, apiPort, namespace)
	events := []*types.Event{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return events, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth.AccessToken))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return events, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return events, err
	}

	err = json.Unmarshal(body, &events)
	if err != nil {
		return events, err
	}

	result := filterEvents(events)

	return result, err
}

func evalAggregate() error {
	auth, err := authenticate()

	if err != nil {
		return err
	}

	events := []*types.Event{}

	for _, namespace := range strings.Split(namespaces, ",") {
		selected, err := getEvents(auth, namespace)

		if err != nil {
			return err
		}

		for _, event := range selected {
			events = append(events, event)
		}
	}

	counters := Counters{}

	entities := map[string]string{}
	checks := map[string]string{}

	for _, event := range events {
		entities[event.Entity.ObjectMeta.Name] = ""
		checks[event.Check.ObjectMeta.Name] = ""

		switch event.Check.Status {
		case 0:
			counters.Ok += 1
		case 1:
			counters.Warning += 1
		case 2:
			counters.Critical += 1
		default:
			counters.Unknown += 1
		}

		counters.Total += 1
	}

	counters.Entities = len(entities)
	counters.Checks = len(checks)

	fmt.Printf("Counters: %+v\n", counters)

	if counters.Total == 0 {
		fmt.Printf("WARNING: No Events returned for Aggregate\n")
		os.Exit(1)
	}

	percent := int((float64(counters.Ok) / float64(counters.Total)) * 100)

	fmt.Printf("Percent OK: %v\n", percent)

	if critPercent != 0 {
		if percent <= critPercent {
			fmt.Printf("CRITICAL: Less than %d%% percent OK (%d%%)\n", critPercent, percent)
			os.Exit(2)
		}
	}

	if warnPercent != 0 {
		if percent <= warnPercent {
			fmt.Printf("WARNING: Less than %d%% percent OK (%d%%)\n", warnPercent, percent)
			os.Exit(1)
		}
	}

	if critCount != 0 {
		if counters.Critical >= critCount {
			fmt.Printf("CRITICAL: %d or more Events are in a Critical state (%d)\n", critCount, counters.Critical)
			os.Exit(2)
		}
	}

	if warnCount != 0 {
		if counters.Warning >= warnCount {
			fmt.Printf("WARNING: %d or more Events are in a Warning state (%d)\n", warnCount, counters.Warning)
			os.Exit(2)
		}
	}

	fmt.Printf("Everything is OK\n")

	return err
}
