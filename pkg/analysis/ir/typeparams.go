package ir

import (
	"fmt"
	"go/token"
	"go/types"
	"strconv"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// TypeParamRenamer rewrites the type parameters in scope in a generic
// function, its receiver's and its enclosing functions', to placeholders
// named by position ("$0", "$1"), so a type-parameter rename such as List[T]
// to List[E] does not change how the function's types are rendered. It
// substitutes type objects rather than text, so a field, method or
// package-level type that shares a type parameter's name is left as is.
type TypeParamRenamer struct {
	subst map[*types.TypeParam]types.Type
	cache map[types.Type]types.Type
	ctxt  *types.Context
}

// NewTypeParamRenamer returns the renamer for fn, or nil when no type
// parameter is in scope; a nil renamer leaves every type unchanged.
func NewTypeParamRenamer(fn *ssa.Function) *TypeParamRenamer {
	var chain []*ssa.Function
	for f := fn; f != nil; f = f.Parent() {
		chain = append(chain, f)
	}
	r := &TypeParamRenamer{subst: make(map[*types.TypeParam]types.Type)}
	// Outermost first, so a closure numbers its enclosing function's type
	// parameters exactly as that function does.
	for i := len(chain) - 1; i >= 0; i-- {
		sig := chain[i].Signature
		for _, tps := range []*types.TypeParamList{sig.RecvTypeParams(), sig.TypeParams()} {
			for j := 0; j < tps.Len(); j++ {
				tp := tps.At(j)
				if _, ok := r.subst[tp]; ok {
					continue
				}
				name := types.NewTypeName(token.NoPos, nil, "$"+strconv.Itoa(len(r.subst)), nil)
				r.subst[tp] = types.NewTypeParam(name, tp.Constraint())
			}
		}
	}
	if len(r.subst) == 0 {
		return nil
	}
	r.cache = make(map[types.Type]types.Type)
	r.ctxt = types.NewContext()
	return r
}

// Rename returns t with every in-scope type parameter replaced by its
// placeholder, or t itself when it mentions none.
func (r *TypeParamRenamer) Rename(t types.Type) types.Type {
	if r == nil || t == nil {
		return t
	}
	if out, ok := r.cache[t]; ok {
		return out
	}
	out := r.rename(t)
	r.cache[t] = out
	return out
}

// FuncName is fn.RelString(from), except that the receiver type and type
// arguments in it are rendered from their types, so the type parameters r
// renames appear by position.
func (r *TypeParamRenamer) FuncName(fn *ssa.Function, from *types.Package) string {
	rel := fn.RelString(from)
	if r == nil {
		return rel
	}
	if parent := fn.Parent(); parent != nil {
		for i, anon := range parent.AnonFuncs {
			if anon == fn {
				return fmt.Sprintf("%s$%d", r.FuncName(parent, from), i+1)
			}
		}
		return rel
	}
	if recv := fn.Signature.Recv(); recv != nil {
		return fmt.Sprintf("(%s).%s", types.TypeString(r.Rename(recv.Type()), types.RelativeTo(from)), fn.Name())
	}
	targs := fn.TypeArgs()
	if fn.Origin() == nil || len(targs) == 0 || !strings.HasSuffix(rel, fn.Name()) {
		return rel
	}
	args := make([]string, len(targs))
	for i, t := range targs {
		args[i] = r.Rename(t).String()
	}
	return strings.TrimSuffix(rel, fn.Name()) + fn.Origin().Name() + "[" + strings.Join(args, ", ") + "]"
}

func (r *TypeParamRenamer) rename(t types.Type) types.Type {
	switch t := t.(type) {
	case *types.TypeParam:
		if p, ok := r.subst[t]; ok {
			return p
		}
	case *types.Alias:
		if u := types.Unalias(t); u != t {
			if out := r.Rename(u); out != u {
				return out
			}
		}
	case *types.Pointer:
		if e := r.Rename(t.Elem()); e != t.Elem() {
			return types.NewPointer(e)
		}
	case *types.Slice:
		if e := r.Rename(t.Elem()); e != t.Elem() {
			return types.NewSlice(e)
		}
	case *types.Array:
		if e := r.Rename(t.Elem()); e != t.Elem() {
			return types.NewArray(e, t.Len())
		}
	case *types.Chan:
		if e := r.Rename(t.Elem()); e != t.Elem() {
			return types.NewChan(t.Dir(), e)
		}
	case *types.Map:
		k, v := r.Rename(t.Key()), r.Rename(t.Elem())
		if k != t.Key() || v != t.Elem() {
			return types.NewMap(k, v)
		}
	case *types.Tuple:
		if vars, changed := r.vars(t); changed {
			return types.NewTuple(vars...)
		}
	case *types.Signature:
		params, pc := r.vars(t.Params())
		results, rc := r.vars(t.Results())
		if pc || rc {
			return types.NewSignatureType(nil, nil, nil, types.NewTuple(params...), types.NewTuple(results...), t.Variadic())
		}
	case *types.Struct:
		fields := make([]*types.Var, t.NumFields())
		tags := make([]string, t.NumFields())
		changed := false
		for i := range fields {
			f := t.Field(i)
			ft := r.Rename(f.Type())
			changed = changed || ft != f.Type()
			fields[i] = types.NewField(f.Pos(), f.Pkg(), f.Name(), ft, f.Embedded())
			tags[i] = t.Tag(i)
		}
		if changed {
			return types.NewStruct(fields, tags)
		}
	case *types.Interface:
		methods := make([]*types.Func, t.NumExplicitMethods())
		embeddeds := make([]types.Type, t.NumEmbeddeds())
		changed := false
		for i := range methods {
			m := t.ExplicitMethod(i)
			sig := r.Rename(m.Type())
			changed = changed || sig != m.Type()
			methods[i] = types.NewFunc(m.Pos(), m.Pkg(), m.Name(), sig.(*types.Signature))
		}
		for i := range embeddeds {
			embeddeds[i] = r.Rename(t.EmbeddedType(i))
			changed = changed || embeddeds[i] != t.EmbeddedType(i)
		}
		if changed {
			return types.NewInterfaceType(methods, embeddeds).Complete()
		}
	case *types.Union:
		terms := make([]*types.Term, t.Len())
		changed := false
		for i := range terms {
			term := t.Term(i)
			tt := r.Rename(term.Type())
			changed = changed || tt != term.Type()
			terms[i] = types.NewTerm(term.Tilde(), tt)
		}
		if changed {
			return types.NewUnion(terms)
		}
	case *types.Named:
		args := t.TypeArgs()
		if args.Len() == 0 {
			break
		}
		renamed := make([]types.Type, args.Len())
		changed := false
		for i := range renamed {
			renamed[i] = r.Rename(args.At(i))
			changed = changed || renamed[i] != args.At(i)
		}
		if changed {
			if inst, err := types.Instantiate(r.ctxt, t.Origin(), renamed, false); err == nil {
				return inst
			}
		}
	}
	return t
}

func (r *TypeParamRenamer) vars(tuple *types.Tuple) ([]*types.Var, bool) {
	vars := make([]*types.Var, tuple.Len())
	changed := false
	for i := range vars {
		v := tuple.At(i)
		vt := r.Rename(v.Type())
		changed = changed || vt != v.Type()
		vars[i] = types.NewParam(v.Pos(), v.Pkg(), v.Name(), vt)
	}
	return vars, changed
}
