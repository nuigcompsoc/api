package utils

import (
    log "github.com/sirupsen/logrus"
    "encoding/json"
    "net/http"
    "net/url"
    "time"
    "io/ioutil"
    "strings"
    "strconv"
)

var c = &http.Client{Timeout: 10 * time.Second}

func GetJson(link string) (map[string]interface{}, bool) {
    var target map[string]interface{}
    r, err := c.Get(link)
    if err != nil {
        log.WithFields(log.Fields{
			"message": "issue resolving " + link,
			"error": err.Error(),
		}).Error("http-util")
        return nil, false
    }

    body, _ := ioutil.ReadAll(r.Body)
    err = json.Unmarshal(body, &target)
    if err != nil {
        log.WithFields(log.Fields{
			"message": "issue unmarshaling json from " + link,
            "body": body,
			"error": err.Error(),
		}).Error("http-util")
        return nil, false
    }
    
    defer r.Body.Close()
    return target, true
}

func PostUrlEncoded(link string, params *url.Values) (map[string]interface{}, bool) {
    r, err := http.NewRequest("POST", link, strings.NewReader(params.Encode()))
    if err != nil {
        log.WithFields(log.Fields{
			"message": "issue generating request for " + link,
			"error": err.Error(),
		}).Error("http-util")
        return nil, false
    }
    r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
    r.Header.Add("Content-Length", strconv.Itoa(len(params.Encode())))

    res, err := c.Do(r)
    if err != nil {
        log.WithFields(log.Fields{
			"message": "issue resolving " + link,
			"error": err.Error(),
		}).Error("http-util")
        return nil, false
    }

    var target map[string]interface{}
    body, _ := ioutil.ReadAll(res.Body)
    err = json.Unmarshal(body, &target)
    if err != nil {
        log.WithFields(log.Fields{
			"message": "issue unmarshaling json from " + link,
            "body": body,
			"error": err.Error(),
		}).Error("http-util")
        return nil, false
    }

    defer res.Body.Close()
    return target, true
}