package helpers

import (
	"github.com/gin-gonic/gin"
	"strings"
	"sort"
)

/*
 * Validates path parameters exist
 * This doesn't care if there are extra parameters in the path
 * it just checks that it contains the required ones
 * /v1/society/compsoc will pass if given compsoc
 * /v1/society will fail if given compsoc
 */
func ValidatePathParameters(c *gin.Context, expectedParameters ...string) bool {
	path := c.Request.URL.Path
	parameters := strings.Split(path[1:], "/") // removing first /
	sort.Strings(parameters)
	
	for _, p := range expectedParameters {
		if (!stringContains(parameters, p)) {
			return false
		}
	}
	return true
}

// Checks top level of string array for element
func stringContains(list []string, s string) bool {
	i := sort.SearchStrings(list, s)
	return i < len(list) && list[i] == s
}