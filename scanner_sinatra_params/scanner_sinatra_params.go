package sinatraParamScanner

import (
	"fmt"
	"regexp"

	"github.com/ryanfaerman/fsm"
)

type sinatraParamScanner struct {
	parameters             []parameter
	validators             []parameter
	fsmInputValidation     thing
	fileName               string //just for logging purposes
	endpointsAnalized      int
	missingValidationCount int
	lineCount              int
}

// New Creates a new Sinatra Param Scanner
func New(fileName string) sinatraParamScanner {
	var parameters []parameter
	var validators []parameter
	fsmInputValidation := thing{State: "no_endpoint"}

	s := sinatraParamScanner{parameters, validators, fsmInputValidation, fileName, 0, 0, 0}
	return s
}

const (
	silent   int = 0
	alert    int = 1
	info     int = 2
	debug    int = 3
	logLevel int = silent
)

//All variables here should be treated as constants
var logNames = []string{"SILENT", "ALERT", "INFO", "DEBUG"}
var regexpEndpointStart = regexp.MustCompile(`^\s*(get|post|put|delete|patch|before)\s'.*\sdo`)
var regexURLParams = regexp.MustCompile(`/:([a-zA-Z0-9-_]+)`)
var regexpEndpointEnd = regexp.MustCompile(`^  end\s?$`)
var regexpEndpointParams = regexp.MustCompile(`params\[\"?:?([a-zA-Z0-9_-]+)\"?\]`)
var regexpEndpointValidation = regexp.MustCompile(`param\s:([a-zA-Z0-9_-]+)\s?,`)
var regexRemoveComments = regexp.MustCompile(`(#.*)`)

// GetViolations returns how many validations are missing
func (s *sinatraParamScanner) GetViolations() int {
	s.checkMissingValidations()
	log(info, "[Lines processed]", s.fileName, s.lineCount)
	log(info, "[Endpoints processed]", s.fileName, s.endpointsAnalized)
	log(info, "[Missing Validations]", s.fileName, s.missingValidationCount)

	return s.missingValidationCount
}

// ScanLine starts scanning the given file for vulnerabilities and seucurity misconfigurations
func (s *sinatraParamScanner) ScanLine(line string) {

	line = regexRemoveComments.ReplaceAllString(line, "")
	s.lineCount++

	if s.fsmInputValidation.CurrentState() == "no_endpoint" {
		if isNewEndpoint(line) {
			s.fsmInputValidation.SetState("endpoint_started")
			log(debug, "[New Endpoint]", s.fileName, ":", s.lineCount, line)
			s.endpointsAnalized++
			s.processNewEndpoint(line)
			return
		}
	}

	if s.fsmInputValidation.CurrentState() == "endpoint_started" {
		//fmt.Println("looking for sinatra params")
		inputValidation := regexpEndpointValidation.FindStringSubmatch(line)
		if len(inputValidation) > 1 {
			//paramValidators := regexSinatraParam.FindStringSubmatch(line)[1]
			s.validators = append(s.validators, parameter{inputValidation[1], s.lineCount})
			log(debug, "[New Validator]", inputValidation[1], line)
			return
		}

		//fmt.Println("looking for parameters use")
		param := regexpEndpointParams.FindStringSubmatch(line)
		if len(param) > 0 {
			s.parameters = append(s.parameters, parameter{param[1], s.lineCount})
			log(debug, "[New Parameter]", param[1], line)
			return
		}

		endpointEnd := regexpEndpointEnd.MatchString(line)
		if endpointEnd {
			log(debug, "[End Endpoint]", s.fileName, s.lineCount, line)
			s.fsmInputValidation.SetState("no_endpoint")
			log(debug, "[Parameters]", s.parameters)
			log(debug, "[Validators]", s.validators)
			s.checkMissingValidations()
			return
		}

		if isNewEndpoint(line) {
			log(debug, "Endpoint end not found -> new endpoint found -> forcing analsys", s.fileName, ":", s.lineCount, line)
			s.checkMissingValidations()
			s.endpointsAnalized++
			s.processNewEndpoint(line)

			return
		}
	}

	// In case the final endpoint end is not found
	//s.checkMissingValidations()
}

func (s *sinatraParamScanner) processNewEndpoint(line string) {
	s.parameters = s.parameters[:0]
	s.validators = s.validators[:0]
	urlParams := regexURLParams.FindAllString(line, -1)
	urlParams = findAndRemoveElement(unique(urlParams), "/:format") //TO DO: don't remove format if it's a "before"?
	urlParamType := createParamFromSlice(urlParams, s.lineCount)
	s.parameters = append(s.parameters, urlParamType...)
	log(debug, "[Url parameters]", s.parameters)
}

func isNewEndpoint(line string) bool {
	newEndpoint := regexpEndpointStart.MatchString(line)
	if newEndpoint {
		return true
	}
	return false
}

func (s *sinatraParamScanner) checkMissingValidations() {
	s.parameters = uniqueParameters(s.parameters)
	for _, param := range s.parameters {
		if !s.isParamInValidators(param.name) {
			log(alert, s.fileName, ":", param.line, " - ", param.name, ": missing validator")
			s.missingValidationCount++
		}
	}
	s.parameters = s.parameters[:0]
	s.validators = s.validators[:0]
}

func (s sinatraParamScanner) isParamInValidators(param string) bool {
	for _, validator := range s.validators {
		if validator.name == param {
			return true
		}
	}
	return false
}

func log(level int, a ...interface{}) {

	if level <= logLevel {
		fmt.Print("[", logNames[level], "] ")
		fmt.Println(a)
	}
}

func createParamFromSlice(urlParams []string, line int) []parameter {
	var output []parameter
	for _, param := range urlParams {
		output = append(output, parameter{param, line})
	}
	return output
}

type parameter struct {
	name string
	line int
}

type thing struct {
	State fsm.State
	// our machine cache
	machine *fsm.Machine
}

// Add methods to comply with the fsm.Stater interface
func (t *thing) CurrentState() fsm.State { return t.State }
func (t *thing) SetState(s fsm.State)    { t.State = s }

// A helpful function that lets us apply arbitrary rulesets to this
// instances state machine without reallocating the machine. While not
// required, it's something I like to have.
func (t *thing) Apply(r *fsm.Ruleset) *fsm.Machine {
	if t.machine == nil {
		t.machine = &fsm.Machine{Subject: t}
	}

	t.machine.Rules = r
	return t.machine
}

//check log lines don't include pii, phone, app name, email...
//check ex-employees is not in any file
