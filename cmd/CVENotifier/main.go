// cmd/main.go
package main

import (
    "bytes"
    "encoding/json"
    "flag"
    "fmt"
    "log"
    "net/http"
    "os"
    "strings"

    "github.com/dark-warlord14/CVENotifier/internal/db"
    "github.com/mmcdole/gofeed"
    "gopkg.in/yaml.v3"
)

type Config struct {
    Keywords []string `yaml:"keywords"`
    HttpPush []string `yaml:"httpPush"`
}

type AttachmentContentBody struct {
    Type string `json:"type"`
    Text string `json:"text"`
    Wrap bool   `json:"wrap"`
}

type AttachmentContent struct {
    Schema  string                  `json:"$schema"`
    Type    string                  `json:"type"`
    Version string                  `json:"version"`
    Body    []AttachmentContentBody `json:"body"`
}

type Attachment struct {
    ContentType string            `json:"contentType"`
    Content     AttachmentContent `json:"content"`
}

type Payload struct {
    Type        string       `json:"type"`
    Attachments []Attachment `json:"attachments"`
}

func main() {
    var configPath string
    flag.StringVar(&configPath, "config", "config.yaml", "/Users/brodynielsen/go_projects/pkg/mod/github.com/dark-warlord14/!c!v!e!notifier@v1.0.0/cmd/CVENotifier/config.yaml")
    flag.Parse()

    data, err := os.ReadFile(configPath)
    if err != nil {
        log.Fatalf("Failed to read config file: %v.\nPlease provide the config file using -config flag.\ne.g., go run cmd/CVENotifier/main.go -config config.yaml", err)
    }

    var cfg Config
    if err := yaml.Unmarshal(data, &cfg); err != nil {
        log.Fatalf("Failed to unmarshal config data: %v", err)
    }

    fp := gofeed.NewParser()
    feed, err := fp.ParseURL("https://vuldb.com/?rss.recent")
    if feed == nil {
        log.Fatalf("Failed to parse RSS feed: %v. Please retry", err)
    }

    databasePath := "CVENotifier.db"
    dbConn, err := db.InitDB(databasePath)
    if err != nil {
        log.Fatalf("Failed to initialize database: %v", err)
    }
    defer dbConn.Close()

    var matchFound = 0

    for _, item := range feed.Items {
        for _, keyword := range cfg.Keywords {
            if strings.Contains(strings.ToLower(item.Title), strings.ToLower(keyword)) {
                matchFound++
                log.Printf("Matched Keyword: %s", keyword)
                log.Printf("Title: %s", item.Title)
                log.Printf("Link: %s", item.Link)
                log.Printf("Published Date: %s", item.Published)
                log.Printf("Categories: %s", strings.Join(item.Categories, ","))

                if len(cfg.HttpPush) > 0 {
                    bodyContents := []AttachmentContentBody{
                        {
                            Type: "TextBlock",
                            Text: fmt.Sprintf("Title: %s | Vendor: Trend Micro | Product: Apex One\nRisk: critical | Local: Yes | Remote: No\nExploit: Yes | Countermeasures: Upgrade\nLink: %s\nPublished Date: %s",
                                item.Title, item.Link, item.Published),
                            Wrap: true,
                        },
                    }
                    attachmentContent := AttachmentContent{
                        Schema:  "http://adaptivecards.io/schemas/adaptive-card.json",
                        Type:    "AdaptiveCard",
                        Version: "1.2",
                        Body:    bodyContents,
                    }

                    attachment := Attachment{
                        ContentType: "application/vnd.microsoft.card.adaptive",
                        Content:     attachmentContent,
                    }

                    payload := Payload{
                        Type:        "Message",
                        Attachments: []Attachment{attachment},
                    }

                    jsonData, err := json.Marshal(payload)
                    if err != nil {
                        log.Printf("Failed to marshal JSON: %v", err)
                        continue
                    }

                    for _, httpPushEndpoint := range cfg.HttpPush {
                        response, err := http.Post(httpPushEndpoint, "application/json", bytes.NewBuffer(jsonData))
                        if err != nil {
                            log.Printf("Failed to send HTTP push notification: %v", err)
                            continue
                        }
                        log.Printf("HTTP push sent successfully to %s with response status: %s", httpPushEndpoint, response.Status)
                    }
                } else {
                    log.Printf("Warning: No HTTP push URL provided in the configuration.")
                }
            }
        }
    }

    if matchFound == 0 {
        log.Printf("Result: No CVE matches found in the vuldb RSS feed")
    }
}
