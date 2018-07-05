package fileutil

import (
	"encoding/json"
	"github.com/CSUNetSec/protoparse/filter"
	"github.com/pkg/errors"
	"io/ioutil"
)

//a filter file should be populated
//straight from a json object
type FilterFile struct {
	MonitoredPrefixes []string
	SourceAses        []uint32
	DestAses          []uint32
	MidPathAses       []uint32
	AnywhereAses      []uint32
}

func (f FilterFile) getFilters() ([]filter.Filter, error) {
	ret := []filter.Filter{}
	if len(f.MonitoredPrefixes) > 0 {
		if fil, err := filter.NewPrefixFilterFromSlice(f.MonitoredPrefixes); err != nil {
			return nil, errors.Wrap(err, "can not create prefix filter from conf")
		} else {
			ret = append(ret, fil)
		}
	}
	if len(f.SourceAses) > 0 {
		if fil, err := filter.NewASFilterFromSlice(f.SourceAses, filter.AS_SOURCE); err != nil {
			return nil, errors.Wrap(err, "can not create source AS filter from conf")
		} else {
			ret = append(ret, fil)
		}
	}

	if len(f.DestAses) > 0 {
		if fil, err := filter.NewASFilterFromSlice(f.SourceAses, filter.AS_DESTINATION); err != nil {
			return nil, errors.Wrap(err, "can not create destination AS filter from conf")
		} else {
			ret = append(ret, fil)
		}
	}

	if len(f.MidPathAses) > 0 {
		if fil, err := filter.NewASFilterFromSlice(f.SourceAses, filter.AS_MIDPATH); err != nil {
			return nil, errors.Wrap(err, "can not create midpath AS filter from conf")
		} else {
			ret = append(ret, fil)
		}
	}

	if len(f.AnywhereAses) > 0 {
		if fil, err := filter.NewASFilterFromSlice(f.SourceAses, filter.AS_ANYWHERE); err != nil {
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
	}
	if err := json.Unmarshal(contents, &ff); err != nil {
		return nil, errors.Wrap(err, "json unmarshal")
	}
	return ff.getFilters()
}
