package edgedict

type Entry struct {
	Name                   string             `json:"name"`
	PhoneticName           string             `json:"phoneticName"`
	Pronunciation          string             `json:"pronunciation"`
	PronunciationAudio     PronunciationAudio `json:"pronunciationAudio"`
	MeaningGroups          []MeaningGroup     `json:"meaningGroups"`
	WordOrigin             string             `json:"wordOrigin"`
	AggregatePartsOfSpeech Item               `json:"aggregatePartsOfSpeech"`
}

type MeaningGroup struct {
	Meanings      []Meaning  `json:"meanings"`
	WordForms     []WordForm `json:"wordForms"`
	PartsOfSpeech []Item     `json:"partsOfSpeech"`
}

type Meaning struct {
	RichDefinitions []RichDefinition `json:"richDefinitions"`
}

type RichDefinition struct {
	Fragments      []RichDefinitionFragment `json:"fragments"`
	Domains        []string                 `json:"domains"`
	Synonyms       []Item                   `json:"synonyms"`
	Examples       []string                 `json:"examples"`
	LabelTags      []string                 `json:"labelTags"`
	Antonyms       []Item                   `json:"antonyms"`
	SubDefinitions []RichDefinition         `json:"subDefinitions"`
}

type RichDefinitionFragment struct {
	Type        string  `json:"_type"`
	Text        string  `json:"text"`
	URL         *string `json:"url"`
	Format      *string `json:"format"`
	Numerator   *string `json:"numerator"`
	Denominator *string `json:"denominator"`
}

type WordForm struct {
	Form string `json:"form"`
	Word Item   `json:"word"`
}

type PronunciationAudio struct {
	ContentURL string `json:"contentUrl"`
}

type Item struct {
	Name string `json:"name"`
}
