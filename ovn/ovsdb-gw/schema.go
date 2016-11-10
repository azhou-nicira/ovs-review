package ovsdb

// DatabaseSchema, defined as <database-schema> in RFC7047
type DatabaseSchema struct {
	Name    string
	Version string
	Chksum  string `json:"chksum,omitempty"`
	Tables  map[string]TableSchema
}

// TableSchema, defined as <table-schema> in RFC7047
type TableSchema struct {
	Columns map[string]CloumnSchema
	MaxRows int        `json:"maxRows:omitempty"`
	IsRoot  bool       `json:"isRoot:omitempty"`
	Indexes [][]string `json:indexes,omitempty"`
}

// ColumnSchema, defined as <column-schema> in RFC7047
type ColumnSchema struct {
	Type      SchemaType
	Ephemeral bool `json:"Ephemeral,omitempty"`
	Mutable   bool `json:"mutable,omitempty"`
}

// SchemaType, defined as <type> in RFC7047
type SchemaType struct {
	Key   string
	value string `json:"value,omitempty"`
	min   int    `json:"min,omitempty"`
	max   int    `json:"max,omitempty"`
}


