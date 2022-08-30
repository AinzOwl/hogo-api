package main

// Create domain whois rest api
// with the ability to check domain availability
// and to get whois information
// and use custom whois servers for checking
// whois servers list: https://www.iana.org/domains/root/db

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/TwiN/whois"
	"github.com/gin-gonic/gin"
)

type NotAvailable struct {
	NotAvailable []NotAvaStr `json:"notAvailable"`
}

type NotAvaStr struct {
	Str string `json:"str"`
}

func checkAva(whois string) bool {
	jsonFile, err := os.Open("notfound.json")
	if err != nil {
		fmt.Println(err)
	}
	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)
	var notAvailable NotAvailable

	json.Unmarshal(byteValue, &notAvailable)

	// check if whois contain value from notfound.json
	for _, value := range notAvailable.NotAvailable {
		// check if whois contain value.Str in it

		if strings.Contains(whois, value.Str) {
			// fmt.Println("Not available")
			// os.Exit(0)
			return true
		}
	}
	return false
}

func availableDomain(context *gin.Context) {

	domain := context.Param("domain")

	// split domain by "." and remove the first element then join it with "."
	tld := strings.Join(strings.Split(domain, ".")[1:], ".")

	if tld == "" {
		context.JSON(http.StatusBadRequest, gin.H{"Message": "Invalid domain"})
	} else {
		b, err := ioutil.ReadFile("avatld.txt")
		if err != nil {
			panic(err)
		}

		isExist, err := regexp.Match(tld, b)
		if err != nil {
			panic(err)
		}
		if isExist {
			nss, err := net.LookupNS(domain)
			if err != nil || len(nss) == 0 {
				client := whois.NewClient()
				response, err := client.Query(domain)
				if err != nil {
					panic(err)
				}

				context.IndentedJSON(http.StatusCreated, gin.H{"Message": "Checked By Whois", "Available": checkAva(response)})

			} else {
				context.IndentedJSON(http.StatusCreated, gin.H{"Message": "Checked By Dns", "Available": false})
			}
		} else {
			context.IndentedJSON(http.StatusCreated, gin.H{"Message": "Unknown TLD", "TLD": tld})
		}
	}

}

func whoiss(context *gin.Context) {

	domain := context.Param("domain")
	tld := strings.Join(strings.Split(domain, ".")[1:], ".")

	if tld == "" {
		context.JSON(http.StatusBadRequest, gin.H{"Message": "Invalid domain"})
	} else {
		b, err := ioutil.ReadFile("avatld.txt")
		if err != nil {
			panic(err)
		}

		isExist, err := regexp.Match(tld, b)
		if err != nil {
			panic(err)
		}
		if isExist {
			nss, err := net.LookupNS(domain)
			if err != nil || len(nss) == 0 {
				client := whois.NewClient()
				response, err := client.Query(domain)
				if err != nil {
					panic(err)
				}

				context.IndentedJSON(http.StatusCreated, gin.H{"Message": "This domain Has no nameservers", "Whois": response})

			} else {
				client := whois.NewClient()
				response, err := client.Query(domain)
				if err != nil {
					panic(err)
				}
				context.IndentedJSON(http.StatusCreated, gin.H{"Whois": response})
			}
		} else {
			context.IndentedJSON(http.StatusCreated, gin.H{"Message": "Unknown TLD", "TLD": tld})
		}
	}
}

func tldes(context *gin.Context) {

	b, err := os.ReadFile("avatld.txt") // just pass the file name
	if err != nil {
		fmt.Print(err)
	}

	s := string(b)

	context.IndentedJSON(http.StatusOK, strings.Split(s, "\n"))
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	router.GET("/ava/:domain", availableDomain)
	router.GET("/whois/:domain", whoiss)
	router.GET("/tld", tldes)
	router.Run(":80")
}
