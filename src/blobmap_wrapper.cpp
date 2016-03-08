//
//   Copyright 2014 QuarksLab
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//

#include "binmap/blobmap.hpp"

#include <boost/python.hpp>

using namespace boost::python;

template <class T> struct call_wrapper {
  typedef T result_type;
  object call_;
  call_wrapper(object &c) : call_(c) {}
  template <class A0> result_type operator()(A0 const &arg0) {
    return extract<result_type>(call_(arg0));
  }
  template <class A0, class A1, class A2>
  result_type operator()(A0 const &arg0, A1 const &arg1, A2 const &arg2) {
    return extract<result_type>(call_(arg0, arg1, arg2));
  }
};
template <> struct call_wrapper<std::string> {
  typedef std::string result_type;
  object call_;
  call_wrapper(object &c) : call_(c) {}
  template <class A0> result_type operator()(A0 const &arg0) {
    boost::python::object obj = call_(arg0);
    return extract<result_type>(boost::python::str(obj));
  }
  template <class A0, class A1, class A2>
  result_type operator()(A0 const &arg0, A1 const &arg1, A2 const &arg2) {
    boost::python::object obj = call_(arg0, arg1, arg2);
    return extract<result_type>(boost::python::str(obj));
  }
};

GraphProjection<std::string> *python_project(BlobMapView const &bmv,
                                             object projection) {
  GraphProjection<std::string> *gp = new GraphProjection<std::string>();
  call_wrapper<std::string> p(projection);
  bmv.project(p, *gp);
  return gp;
}

BlobMapView *python_filter(BlobMapView const &bmv, object filter) {
  BlobMapView *og = new BlobMapView(bmv.metadata());
  call_wrapper<bool> f(filter);
  bmv.filter(f, *og);
  return og;
}
BlobMapView *python_induced_successors(BlobMapView const &bmv,
                                       boost::filesystem::path const &needle) {
  BlobMapView *og = new BlobMapView(bmv.metadata());
  bmv.induced_successors(*og, needle);
  return og;
}
BlobMapView *
python_induced_predecessors(BlobMapView const &bmv,
                            boost::filesystem::path const &needle) {
  BlobMapView *og = new BlobMapView(bmv.metadata());
  bmv.induced_predecessors(*og, needle);
  return og;
}
BlobMapView *python_induced_graph(BlobMapView const &bmv,
                                  boost::filesystem::path const &needle) {
  BlobMapView *og = new BlobMapView(bmv.metadata());
  bmv.induced_graph(*og, needle);
  return og;
}

BlobMapView *python_last(BlobMap const &bm) {
  BlobMapView *bmv = new BlobMapView(bm.metadata());
  bm.back(*bmv);
  return bmv;
}

BlobMapDiff *python_diff(BlobMapView const &self, BlobMapView const &other) {
  BlobMapDiff *bmd = new BlobMapDiff();
  self.diff(*bmd, other);
  return bmd;
}


template <class T> struct to_python_set {
  static PyObject *convert(boost::unordered_set<T> const &s) {
    PyObject *obj = PySet_New(0);
    for (typename boost::unordered_set<T>::const_iterator iter = s.begin();
         iter != s.end(); ++iter)
      PySet_Add(obj, incref(object(*iter).ptr()));
    return obj;
  }
};

template <class K, class V> struct to_python_dict {
  static PyObject *convert(boost::unordered_map<K, V> const &s) {
    PyObject *obj = PyDict_New();
    for (typename boost::unordered_map<K, V>::const_iterator iter = s.begin();
         iter != s.end(); ++iter)
      PyDict_SetItem(obj, incref(object(iter->first).ptr()),
                     incref(object(iter->second).ptr()));
    return obj;
  }
};
template <class K, class V> struct to_python_sdict {
  static PyObject *convert(std::map<K, V> const &s) {
    PyObject *obj = PyDict_New();
    for (typename std::map<K, V>::const_iterator iter = s.begin();
         iter != s.end(); ++iter)
      PyDict_SetItem(obj, incref(object(iter->first).ptr()),
                     incref(object(iter->second).ptr()));
    return obj;
  }
};
struct to_python_bfp {
  static PyObject *convert(boost::filesystem::path const &p) {
    std::string const s = p.string();
    return incref(object(s).ptr());
  }
};
struct to_python_hardening_feature_t {
  static PyObject *convert(MetadataInfo::hardening_feature_t const &hf) {
    static const char * table[] = {
      "pie",
      "stack-protected",
      "fortified",
      "read-only-relocations",
      "immediate-binding",
      /* PE specific features */
      "pe-stack-protected",
      "pe-safe-seh",
      "pe-dynamic-base",
      "pe-high-entropy-va",
      "pe-force-integrity",
      "pe-nx-compat",
      "pe-appcontainer",
      "pe-guard-cf",
    };
    return incref(object(table[hf]).ptr());
  }
};

namespace {
tuple tuple_to_python(boost::tuples::null_type) { return tuple(); }

template <class H, class T>
tuple tuple_to_python(boost::tuples::cons<H, T> const &x) {
  return tuple(make_tuple(x.get_head()) + tuple_to_python(x.get_tail()));
}
}

template <class T> struct to_python_tuple {
  static PyObject *convert(T const &x) {
    return incref(tuple_to_python(x).ptr());
  }
};

object python_added(BlobMapDiff const &self) {
  return object(self.added_nodes);
}
object python_removed(BlobMapDiff const &self) {
  return object(self.removed_nodes);
}
object python_updated(BlobMapDiff const &self) { return object(self.updated); }

object python_getitem(BlobMapView const &self, std::string const &name) {
  return object(self[name]);
}

object python_successors(BlobMapView const &self, std::string const &name) {
  Graph::successors_type succs;
  self.successors(succs, name);
  return object(succs);
}
object python_predecessors(BlobMapView const &self, std::string const &name) {
  Graph::successors_type preds;
  self.predecessors(preds, name);
  return object(preds);
}

BlobMapView *python_blobmap_item(BlobMap const &self,
                                 BlobMap::graph_key_type key) {
  BlobMapView *bmv = new BlobMapView(self.metadata());
  self.at(*bmv, key);
  return bmv;
}

std::string python_json(BlobMapView const &self) {
  std::string out;
  self.json(out);
  return out;
}

BOOST_PYTHON_MODULE(blobmap) {
  /* the automatic converter / code wrappers */
  to_python_converter<boost::unordered_set<std::string>,
                      to_python_set<std::string> >();
  to_python_converter<boost::unordered_set<MetadataInfo::hardening_feature_t>,
                      to_python_set<MetadataInfo::hardening_feature_t> >();
  to_python_converter<boost::unordered_map<std::string, NodeDiff>,
                      to_python_dict<std::string, NodeDiff> >();
  to_python_converter<boost::unordered_set<boost::filesystem::path>,
                      to_python_set<boost::filesystem::path> >();
  to_python_converter<std::map<boost::filesystem::path, NodeDiff>,
                      to_python_sdict<boost::filesystem::path, NodeDiff> >();
  to_python_converter<boost::filesystem::path, to_python_bfp>();
  to_python_converter<MetadataInfo::hardening_feature_t, to_python_hardening_feature_t>();
  {
    typedef boost::tuples::cons<
        long const &,
        boost::tuples::cons<BlobMapView, boost::tuples::null_type> > tuple_type;
    to_python_converter<tuple_type, to_python_tuple<tuple_type> >();
  }
  {
    typedef boost::tuples::cons<
        boost::filesystem::path,
        boost::tuples::cons<MetadataInfo, boost::tuples::null_type> >
    tuple_type;
    to_python_converter<tuple_type, to_python_tuple<tuple_type> >();
  }

  implicitly_convertible<std::string, boost::filesystem::path>();

  // This will
  // * enable user-defined docstrings
  // * enable python signatures,
  // * disable C++ signatures
  boost::python::docstring_options local_docstring_options(true, false, false);
  scope().attr("__doc__") =
      "manipulation of binmap database\n\n"
      "This module manipulates database created by the ``binmap`` tool.\n"
      "The primary step is thus to create such a database (see ``binmap scan "
      "--help``),\n"
      "then to load it using the BlobMap class\n";

  class_<BlobMap>(
      "BlobMap",
      "Abstraction of software dependency graphs\n"
      "\n"
      "Gives access to all the (time stamp, blobmapview) pairs stored in the "
      "associated database\n"
      "A BlobmapView represents a view of the dependencies at a given time\n"
      "and provides a dict-like interface, with time stamps as keys and "
      "BlobmapBiew as values\n",
      init<std::string>("BlobMap(database_path) -> BlobMap\n"))
      /* dictionary interface */
      .def("__len__", &BlobMap::size,
           "len(blobmap) -> int\n"
           "Number of BlobmapViews stored in the blobmap")
      .def("last", &python_last, return_value_policy<manage_new_object>(),
           "blobmap.last() -> BlobMapView\n"
           "Yields the most recent view stored in the blobmap")
      .def("keys", range(&BlobMap::kbegin, &BlobMap::kend),
           "blobmap.keys() -> iterator\nYields an Iterator over the timestamps "
           "stored in the blobmap")
      .def("values", range(&BlobMap::vbegin, &BlobMap::vend),
           "blobmap.values() -> iterator\nYields an Iterator over the "
           "BlobmapViews stored in the blobmap")
      .def("__iter__", range(&BlobMap::vbegin, &BlobMap::vend),
           "iter(blobmap) -> iterator\nYields an Iterator over the "
           "BlobmapViews stored in the blobmap")
      .def("items", range(&BlobMap::begin, &BlobMap::end),
           "blobmap.items() -> iterator\nYields an Iterator over the "
           "(timestamp,BlobmapBiew) pairs stored in the blobmap")
      .def("__getitem__", &python_blobmap_item,
           return_value_policy<manage_new_object>(),
           "blobmap[timestamp] -> BlobmapBiew\nGiven a time stamp, retrieves "
           "the associated BlobmapView");

  class_<BlobMapView>(
      "BlobMapView",
      "View of the system dependencies at a given a time\n"
      "\n"
      "A BlobmapView wraps the dependency graph and the associated metadata\n"
      "It provides a dict-like interface with absolute paths as keys and "
      "MetadataInfo as values\n"
      "as well as a few high-level graph operations\n",
      no_init)
      /* dictionary interface */
      .def("__len__", &BlobMapView::size,
           "len(blobmapview) -> int\nNumber of paths stored in the blobmapview")
      .def("__iter__", range(&BlobMapView::vbegin, &BlobMapView::vend),
           "iter(blobmapview) -> iterator\nRetrieves an iterator over the "
           "MetadataInfo of the BlobmapView")
      .def("values", range(&BlobMapView::vbegin, &BlobMapView::vend),
           "blobmapview.values() -> iterator\nRetrieves an iterator over the "
           "MetadataInfo of the BlobmapView")
      .def("keys", range(&BlobMapView::kbegin, &BlobMapView::kend),
           "blobmapview.keys() -> iterator\nRetrieves an iterator over the "
           "paths of the BlobmapView")
      .def("items", range(&BlobMapView::begin, &BlobMapView::end),
           "blobmapview.items() -> iterator\nRetrieves an iterator over the "
           "(path, metadatainfo) pairs of the BlobmapView")
      .def("__getitem__", &python_getitem,
           "blobmapview[path] -> MetdataInfo\nGets a node MetadataInfo based "
           "on its absolute filename")

      /* graph interface */
      .def("has_path", &BlobMapView::has_path,
           "blobmapview.has_path(path0, path1) -> Bool\nTrue if there is a "
           "dependency between the two given absolute file paths")
      .def("successors", &python_successors,
           "blobmapview.successors(path) -> set\nSet of absolute file paths "
           "from which the given node depends")
      .def("predecessors", &python_predecessors,
           "blobmapview.predecessors(path) -> set\nSet of absolute file paths "
           "depending on the given node")
      .def("induced_successors", &python_induced_successors,
           return_value_policy<manage_new_object>(),
           "blobmapview.induced_successors(path) -> BlobmapView\n"
           "Builds the induced subgraph of all nodes that have a path from the "
           "given node\n")
      .def("induced_predecessors", &python_induced_predecessors,
           return_value_policy<manage_new_object>(),
           "blobmapview.induced_predecessors(path) -> BlobmapView\n"
           "Builds the induced subgraph of all nodes that have a path to the "
           "given node\n")
      .def("induced_graph", &python_induced_graph,
           return_value_policy<manage_new_object>(),
           "blobmapview.induced_graph(path) -> BlobmapView\n"
           "Builds the induced subgraph of all nodes that ve a path from or to "
           "the given node\n")

      /* graph operations */
      .def("filter", &python_filter, return_value_policy<manage_new_object>(),
           "blobmapview.filter((path, metadata, blobmapview) -> Bool) -> "
           "BlobmapView\n"
           "Filter the view according to a filter function, returning a new "
           "BlobmapView where only the nodes matching the function are kept\n"
           "The filter predicates returns a boolean from a 3-uplet (path of "
           "current node, associated metadata, current blobmapview)\n")
      .def("diff", &python_diff, return_value_policy<manage_new_object>(),
           "blobmapview.diff(otherblobmapview) -> BlobMapDiff\n"
           "Yields an object representing the difference between two views")
      .def("project", &python_project, return_value_policy<manage_new_object>(),
           "blobmapview.project(Metadata -> field) -> GraphProjection\n"
           "Project the BlobMapView in a new space, getting a GraphProjection "
           "obect.\n"
           "The projection is made using argument function that takes a "
           "MetadataInfo and returns one of its field")
      .def("dot", &BlobMapView::dot, "blobmapview.dot(filename) -> None\n"
                                     "Dumps view in a dot file, suitable for "
                                     "processing with the graphviz suite")
      .def("json", &python_json, "blobmapview.json() -> str\n"
                                 "Dumps view in JSON format");

  class_<NodeDiff>(
      "NodeDiff",
      "Abstraction of the difference between two nodes of two graphs\n"
      "\n"
      "Only meant to be read through the ``str`` call\n")
      .def(self_ns::str(self));

  class_<Hash>("Hash", "Abstraction of the hash of a file\n")
      .def(self_ns::str(self));

  class_<MetadataInfo>("MetadataInfo", "Metdata associated to a node", no_init)
      .add_property(
           "name",
           make_function((std::string const & (MetadataInfo::*)() const) &
                             MetadataInfo::name,
                         return_value_policy<return_by_value>()),
           "Canonical name")
      .add_property("hash",
                    make_function((Hash const & (MetadataInfo::*)() const) &
                                      MetadataInfo::hash,
                                  return_value_policy<return_by_value>()),
                    "File hash")
      .add_property(
           "version",
           make_function((std::string const & (MetadataInfo::*)() const) &
                             MetadataInfo::version,
                         return_value_policy<return_by_value>()),
           "File version number, if found")
      .add_property(
           "exported_symbols",
           make_function((boost::unordered_set<std::string> const & (MetadataInfo::*)() const) &
                             MetadataInfo::exported_symbols,
                         return_value_policy<return_by_value>()),
           "set of exported symbols")
      .add_property(
           "imported_symbols",
           make_function((boost::unordered_set<std::string> const & (MetadataInfo::*)() const) &
                             MetadataInfo::imported_symbols,
                         return_value_policy<return_by_value>()),
           "set of imported symbols")
      .add_property(
           "hardening_features",
           make_function((boost::unordered_set<MetadataInfo::hardening_feature_t> const & (MetadataInfo::*)() const) &
                             MetadataInfo::hardening_features,
                         return_value_policy<return_by_value>()),
           "set of hardening features")
      .def(self_ns::str(self));

  class_<BlobMapDiff>("BlobMapDiff",
                      "Abstraction of the difference between two views")
      .add_property("added", python_added, "Nodes added to the view")
      .add_property("removed", &python_removed, "Nodes removed from the view")
      .add_property("updated", &python_updated,
                    "Nodes of the view that have updated metadata");

  class_<GraphProjection<std::string> >(
      "GraphProjection", "Simplified graph whose key have changed due to a "
                         "projection\n\nThis graph can only be dumped in a dot "
                         "file...",
      no_init).def("dot", &GraphProjection<std::string>::dot,
                   "Dump graph in a dot file");
}
