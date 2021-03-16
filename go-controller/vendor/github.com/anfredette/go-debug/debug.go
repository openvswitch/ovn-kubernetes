package go_debug

import (
	"fmt"
	"runtime"
	"strings"
)

func getFileNameFromPath(path string) string {
	splitPath := strings.Split(path, "/")

	length := len(splitPath)
	if length <= 0 {
		return "FILE_NAME_ERROR"
	}
	return splitPath[length-1]
}

func getFunctionName(path string) string {
	splitPath := strings.Split(path, "/")

	length := len(splitPath)
	if length <= 0 {
		return "FILE_NAME_ERROR"
	}
	return splitPath[length-1]
}

func Location() string {
	function, file, line, _ := runtime.Caller(1)

	fileName := getFileNameFromPath(file)
	functionName := getFunctionName(runtime.FuncForPC(function).Name())

	return fmt.Sprintf("%s, %s(), Line: %d", fileName, functionName, line)
}
