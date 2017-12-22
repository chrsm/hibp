package hibp

import "time"

type Breaches []Breach

type Breach struct {
	Name   string
	Title  string
	Domain string

	BreachDate   tISO8601Short
	AddedDate    tISO8601
	ModifiedDate tISO8601

	PwnCount int

	Description string
	DataClasses []string

	IsVerified   bool
	IsFabricated bool
	IsSensitive  bool
	IsRetired    bool
	IsSpamList   bool
}

type tISO8601Short time.Time

func (t *tISO8601Short) String() string {
	return time.Time(*t).String()
}

func (t *tISO8601Short) UnmarshalJSON(src []byte) error {
	stdt, err := time.ParseInLocation(`"2006-01-02"`, string(src), time.FixedZone("", 0))
	if err == nil {
		*t = tISO8601Short(stdt)
	}

	return err
}

type tISO8601 time.Time

func (t *tISO8601) String() string {
	return time.Time(*t).String()
}

func (t *tISO8601) UnmarshalJSON(src []byte) error {
	stdt, err := time.ParseInLocation(`"2006-01-02T15:04:05Z"`, string(src), time.FixedZone("", 0))
	if err == nil {
		*t = tISO8601(stdt)
	}

	return err
}
