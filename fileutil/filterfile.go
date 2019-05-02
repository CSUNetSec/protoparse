package fileutil

import (
	"encoding/json"
	"github.com/CSUNetSec/protoparse/filter"
	"github.com/pkg/errors"
	"io/ioutil"
)

// FilterFile structs should be populated
// straight from a json object
type FilterFile struct {
	MonitoredPrefixes []string
	SourceASes        []uint32
	DestASes          []uint32
	MidPathASes       []uint32
	AnywhereASes      []uint32
}

// XXX getFilters now only filters on advertized prefixes. we need to pass an option from filterfile on what
// types it should invoke
func (f FilterFile) getFilters() ([]filter.Filter, error) {
	ret := []filter.Filter{}
	if len(f.MonitoredPrefixes) > 0 {
		if fil, err := filter.NewPrefixFilterFromSlice(f.MonitoredPrefixes, filter.AdvPrefix); err != nil {
			return nil, errors.Wrap(err, "can not create prefix filter from conf")
		} else {
			ret = append(ret, fil)
		}
	}
	if len(f.SourceASes) > 0 {
		if fil, err := filter.NewASFilterFromSlice(f.SourceASes, filter.AS_SOURCE); err != nil {
			return nil, errors.Wrap(err, "can not create source AS filter from conf")
		} else {
			ret = append(ret, fil)
		}
	}

	if len(f.DestASes) > 0 {
		if fil, err := filter.NewASFilterFromSlice(f.SourceASes, filter.AS_DESTINATION); err != nil {
			return nil, errors.Wrap(err, "can not create destination AS filter from conf")
		} else {
			ret = append(ret, fil)
		}
	}

	if len(f.MidPathASes) > 0 {
		if fil, err := filter.NewASFilterFromSlice(f.SourceASes, filter.AS_MIDPATH); err != nil {
			return nil, errors.Wrap(err, "can not create midpath AS filter from conf")
		} else {
			ret = append(ret, fil)
		}
	}

	if len(f.AnywhereASes) > 0 {
		if fil, err := filter.NewASFilterFromSlice(f.SourceASes, filter.AS_ANYWHERE); err != nil {
			return nil, errors.Wrap(err, "can not create anywhere AS filter from conf")
		} else {
			ret = append(ret, fil)
		}
	}
	return ret, nil
}

func NewFiltersFromFile(a string) ([]filter.Filter, error) {
	var ff FilterFile
	if contents, err := ioutil.ReadFile(a); err != nil {
		return nil, err
	} else {
		if err := json.Unmarshal(contents, &ff); err != nil {
			return nil, errors.Wrap(err, "json unmarshal")
		}
	}
	return ff.getFilters()
}
