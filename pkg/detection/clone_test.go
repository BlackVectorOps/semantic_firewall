package detection

import (
	"reflect"
	"testing"
)

// Clone shares no slice, pointer or map with the original. The fixture
// fills every slice, pointer and map field of Signature, recursively, by
// reflection, so such a field added without a copy in Clone fails here.
// Interface and array fields are neither filled nor checked, and a map's
// values are not checked for sharing; Signature has no interface, array or
// map fields.
func TestSignatureClone_SharesNothing(t *testing.T) {
	var sig Signature
	fill(reflect.ValueOf(&sig).Elem())
	clone := sig.Clone()
	if !reflect.DeepEqual(sig, clone) {
		t.Fatalf("Clone = %+v; want a copy of %+v", clone, sig)
	}
	assertDisjoint(t, "Signature", reflect.ValueOf(sig), reflect.ValueOf(clone))
}

// fill gives every string a value and every slice, pointer and map an
// element, recursively.
func fill(v reflect.Value) {
	switch v.Kind() {
	case reflect.String:
		v.SetString("x")
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).CanSet() {
				fill(v.Field(i))
			}
		}
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fill(s.Index(0))
		v.Set(s)
	case reflect.Pointer:
		p := reflect.New(v.Type().Elem())
		fill(p.Elem())
		v.Set(p)
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		k, e := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
		fill(k)
		fill(e)
		m.SetMapIndex(k, e)
		v.Set(m)
	}
}

// assertDisjoint fails if any slice, pointer or map reachable from a is
// shared with the corresponding one in b.
func assertDisjoint(t *testing.T, path string, a, b reflect.Value) {
	t.Helper()
	switch a.Kind() {
	case reflect.Struct:
		for i := 0; i < a.NumField(); i++ {
			assertDisjoint(t, path+"."+a.Type().Field(i).Name, a.Field(i), b.Field(i))
		}
	case reflect.Slice:
		if !a.IsNil() && a.Len() > 0 && a.Pointer() == b.Pointer() {
			t.Errorf("%s shares its backing array", path)
		}
		for i := 0; i < a.Len() && i < b.Len(); i++ {
			assertDisjoint(t, path+"[]", a.Index(i), b.Index(i))
		}
	case reflect.Pointer:
		if !a.IsNil() {
			if a.Pointer() == b.Pointer() {
				t.Errorf("%s shares its pointee", path)
			}
			assertDisjoint(t, path, a.Elem(), b.Elem())
		}
	case reflect.Map:
		if !a.IsNil() && a.Pointer() == b.Pointer() {
			t.Errorf("%s shares its map", path)
		}
	}
}
