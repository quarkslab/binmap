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

/* blobmap: Binmap core data structure
 *
 * Implementation of blobmap.hpp interface
 */
#include "binmap/blobmap.hpp"
#include "binmap/log.hpp"

#include <boost/foreach.hpp>
#include <boost/archive/text_iarchive.hpp>

#include <algorithm>
#include <iterator>
#include <ctime>
#include <ciso646>

/******************************
 * BlobMapDiff Implementation
 */

namespace {
#ifdef __linux__
// pretty pint helper: prints elements from ``iterable'' separated by a comma
template <class T> struct line_formater {
  T const &iterable;
  line_formater(T const &iterable) : iterable(iterable) {}
};
template <class T>
std::ostream &operator<<(std::ostream &os, line_formater<T> const &lf) {
  typename T::const_iterator iter = lf.iterable.begin();
  if (iter != lf.iterable.end()) {
    os << *iter;
    for (++iter; iter != lf.iterable.end(); ++iter)
      os << ", " << *iter;
  }
  return os;
}

template <class T> line_formater<T> make_line_formater(T const &iterable) {
  return line_formater<T>(iterable);
}
#endif
}

// a diff is empty if they have the same metadata and the same dependencies
bool NodeDiff::empty() const {
  return mdis.first == mdis.second and deps.first == deps.second;
}

BlobMapDiff::BlobMapDiff() {}

#ifdef __linux__
// prints a diff using a typical
// ++++ new value
// ---- old value
// format
std::ostream &operator<<(std::ostream &os, NodeDiff const &nd) {
  if (nd.mdis.first != nd.mdis.second) {
    os << "metadata changes:" << std::endl
       << '-' << nd.mdis.first
       << '+' << nd.mdis.second;
  }
  if (nd.deps.first != nd.deps.second) {
    boost::unordered_set<boost::filesystem::path> added_deps;
    std::set_difference(
        nd.deps.first.begin(), nd.deps.first.end(), nd.deps.second.begin(),
        nd.deps.second.end(),
        std::insert_iterator<boost::unordered_set<boost::filesystem::path> >(
            added_deps, added_deps.end()));

    boost::unordered_set<boost::filesystem::path> removed_deps;
    std::set_difference(
        nd.deps.second.begin(), nd.deps.second.end(), nd.deps.first.begin(),
        nd.deps.first.end(),
        std::insert_iterator<boost::unordered_set<boost::filesystem::path> >(
            removed_deps, removed_deps.end()));
    //TODO: fix this for windows
    os << "Dependency changes:" << std::endl
       << '-' << make_line_formater(removed_deps) << std::endl
       << '+' << make_line_formater(added_deps) << std::endl;
  }
  return os;
}
#endif

/******************************
 * BlobMapView Implementation
 */

// builds a view of the blobmap out of a ``graph'' and the global ``metadata''
BlobMapView::BlobMapView(boost::shared_ptr<Metadata const> const &metadata,
                         Graph const &graph)
    : metadata_(metadata), graph_(graph) {}

// read only access to the associated metadata
boost::shared_ptr<Metadata const> const &BlobMapView::metadata() const {
  return metadata_;
}

// read only access to the underlying graph
Graph const &BlobMapView::graph() const { return graph_; }

// dumps the view in Graphviz's dot format
void BlobMapView::dot(boost::filesystem::path const &path) const {
  graph_.dot(path);
}

// dump the view in json format
// the structure is:
// {'nodes':
//   [
//    {'path': '<path value>',
//     'meta':
//        { 'version': '<version value>',
//          'hash': '<hash value>',
//          'name': '<name value>'
//        },
//     'nbChildren': '<nbChildren value>'
//     },
//     ...
//   ],
//  'links':
//    [
//      {'source': '<source value>',
//       'target': '<target value>'
//      },
//      ...
//    ]
// }
void BlobMapView::json(std::string &to) const {
  std::stringstream oss_nodes;
  std::stringstream oss_links;
  for (Graph::vertex_iterator iter = graph_.begin(), end = graph_.end();
       iter != end; ++iter) {
    boost::filesystem::path const &filename = graph_.key(*iter);
    Hash const &hash = graph_.hash(filename);
    MetadataInfo const &minfo = (*metadata_)[hash];
    Graph::successors_type succs;
    successors(succs, filename);

    //TODO: .string() should be .native() but on windows we'd get a std::wstring()
    oss_nodes << "{\"path\":\"" << filename.string()
              << "\", "
                 "\"meta\": {\"version\":\"" << minfo.version() << "\", "
                                                                   "\"hash\":\""
              << hash.str() << "\", "
                               "\"name\":\"" << minfo.name()
              << "\""
                 "},"
                 "\"nbChildren\":" << succs.size() << "},";
    BOOST_FOREACH(boost::filesystem::path const & succ, succs) {
      oss_links << "{\"source\":\"" << filename.string()
                << "\", "
                   "\"target\":" << succ << ""
                                              "},";
    }
  }
  std::string nodes = oss_nodes.str();
  nodes.resize(nodes.size() - 1);
  std::string links = oss_links.str();
  links.resize(links.size() - 1);

  to = "{\"nodes\": [" + nodes + "], \"links\": [" + links + "]}";
}

// set the graph attribute
void BlobMapView::graph(Graph const &graph) { graph_ = graph; }

// number of nodes in the graph
size_t BlobMapView::size() const { return graph_.size(); }

namespace {
// various functors to check the relationship between two nodes of a graph
struct is_successor_of {
  boost::filesystem::path const &self_;
  is_successor_of(boost::filesystem::path const &self) : self_(self) {}

  bool operator()(boost::filesystem::path const &to, MetadataInfo const &,
                  BlobMapView const &view) const {
    return view.has_path(self_, to);
  }
};
struct is_predecessor_of {
  boost::filesystem::path const &self_;
  is_predecessor_of(boost::filesystem::path const &self) : self_(self) {}

  bool operator()(boost::filesystem::path const &from, MetadataInfo const &,
                  BlobMapView const &view) const {
    return view.has_path(from, self_);
  }
};
struct is_connected_to {
  boost::filesystem::path const &self_;
  is_connected_to(boost::filesystem::path const &self) : self_(self) {}

  bool operator()(boost::filesystem::path const &node, MetadataInfo const &,
                  BlobMapView const &view) const {
    return view.has_path(node, self_) || view.has_path(self_, node);
  }
};
}

// compute the graph of all nodes that have a path from or to ``key''
void BlobMapView::induced_graph(BlobMapView &succ,
                                boost::filesystem::path const &key) const {
  return filter(is_connected_to(key), succ);
}

// compute the graph of all nodes that have a path from ``key''
void BlobMapView::induced_successors(BlobMapView &succ,
                                     boost::filesystem::path const &key) const {
  return filter(is_successor_of(key), succ);
}

// compute the graph of all nodes that have a path to ``key''
void
BlobMapView::induced_predecessors(BlobMapView &succ,
                                  boost::filesystem::path const &key) const {
  return filter(is_predecessor_of(key), succ);
}

// iterator over the values
MetadataIterator<Graph> BlobMapView::vbegin() const {
  return MetadataIterator<Graph>(graph_, graph_.begin(), metadata_);
}
MetadataIterator<Graph> BlobMapView::vend() const {
  return MetadataIterator<Graph>(graph_, graph_.end(), metadata_);
}

// iterator over the keys
KeyIterator<Graph> BlobMapView::kbegin() const {
  return KeyIterator<Graph>(graph_, graph_.begin());
}
KeyIterator<Graph> BlobMapView::kend() const {
  return KeyIterator<Graph>(graph_, graph_.end());
}

// iterator over the items
boost::zip_iterator<boost::tuple<KeyIterator<Graph>, MetadataIterator<Graph> > >
BlobMapView::begin() const {
  return boost::make_zip_iterator(boost::make_tuple(kbegin(), vbegin()));
}
boost::zip_iterator<boost::tuple<KeyIterator<Graph>, MetadataIterator<Graph> > >
BlobMapView::end() const {
  return boost::make_zip_iterator(boost::make_tuple(kend(), vend()));
}

// access the values of the graph through the keys
MetadataInfo BlobMapView::
operator[](boost::filesystem::path const &filename) const {
  return (*metadata_)[graph_.hash(filename)];
}

// check whether there is a path from ``from'' to ``to''
// first call is O(n^2) then O(1)
bool BlobMapView::has_path(boost::filesystem::path const &from,
                           boost::filesystem::path const &to) const {
  return graph_.has_path(from, to);
}

// get the successors of ``key''
void BlobMapView::successors(Graph::successors_type &succs,
                             boost::filesystem::path const &key) const {
  return graph_.successors(succs, key);
}

// get the predecessors of ``key''
void BlobMapView::predecessors(Graph::successors_type &preds,
                               boost::filesystem::path const &key) const {
  return graph_.predecessors(preds, key);
}

// computes the difference between two views, as a ``BlobMapDiff''
void BlobMapView::diff(BlobMapDiff &diff, BlobMapView const &other) const {

  for (Graph::vertex_iterator iter = graph_.begin(), end = graph_.end();
       iter != end; ++iter) {
    boost::filesystem::path const &filename = graph_.key(*iter);
    if (other.graph_.has_node(filename)) {
      NodeDiff &ndiff = diff.updated[filename];

      Hash const &self_hash = graph_.hash(filename);
      Hash const &other_hash = other.graph_.hash(filename);

      ndiff.mdis.first = (*metadata_)[self_hash];
      ndiff.mdis.second = (*other.metadata_)[other_hash];

      graph_.successors(ndiff.deps.first, filename);
      other.graph_.successors(ndiff.deps.second, filename);
      if (ndiff.empty())
        diff.updated.erase(filename);
    } else {
      diff.removed_nodes.insert(filename);
    }
  }

  for (Graph::vertex_iterator iter = other.graph_.begin(),
                              end = other.graph_.end();
       iter != end; ++iter) {
    boost::filesystem::path const &filename = other.graph_.key(*iter);
    if (not graph_.has_node(filename))
      diff.added_nodes.insert(filename);
  }
}

/******************************
 * Blobmap Implementation
 */

// get the metadata
boost::shared_ptr<Metadata const> BlobMap::metadata() const {
  return metadata_;
}

// set the metadata
boost::shared_ptr<Metadata> BlobMap::metadata() { return metadata_; }

// true if there is at least one graph in the blobmap
bool BlobMap::empty() const { return graphs_.empty(); }

// create a new empty graph associated to ``key'' and add it to the blobmap
Graph &BlobMap::create(graph_key_type const &key) {
  assert(graphs_.find(key) == graphs_.end());
  return *(graphs_[key] = new Graph());
}

// create a new blobmap and fill it with the content of the database ``archive_path''
BlobMap::BlobMap(boost::filesystem::path const &archive_path)
    : metadata_(new Metadata()) {
    std::ifstream ifs(archive_path.string().c_str(), std::ios::binary);
    if (ifs) {
      boost::archive::text_iarchive ia(ifs);
      ia & *this;
    }
}

// destroys the blobmap and flush its content to the db
// note that the flush is *not* done before
BlobMap::~BlobMap() {
}

// get the most recent graph in the blobmap
void BlobMap::back(BlobMapView &bmv) const {
  return bmv.graph((*this)[back_key()]);
}

// builds the view associated to ``key''
void BlobMap::at(BlobMapView &bmv, graph_key_type const &key) const {
  return bmv.graph((*this)[key]);
}

// iterate over keys
MapKeyIterator<BlobMap::graph_map_t> BlobMap::kbegin() const {
  return graphs_.begin();
}
MapKeyIterator<BlobMap::graph_map_t> BlobMap::kend() const {
  return graphs_.end();
}

// iterate over values
MapValueIterator<BlobMap::graph_map_t> BlobMap::vbegin() const {
  // fetch all graphs to prepare for the iteration process
  // this is costly...
  BOOST_FOREACH(graph_map_t::value_type const& kv, graphs_) {
    fetch_(kv.first);
  }
  return MapValueIterator<BlobMap::graph_map_t>(metadata_, graphs_.begin());
}
MapValueIterator<BlobMap::graph_map_t> BlobMap::vend() const {
  return MapValueIterator<BlobMap::graph_map_t>(metadata_, graphs_.end());
}

// iterate over items
boost::zip_iterator<boost::tuple<MapKeyIterator<BlobMap::graph_map_t>,
                                 MapValueIterator<BlobMap::graph_map_t> > >
BlobMap::begin() const {
  return boost::make_zip_iterator(boost::make_tuple(kbegin(), vbegin()));
}
boost::zip_iterator<boost::tuple<MapKeyIterator<BlobMap::graph_map_t>,
                                 MapValueIterator<BlobMap::graph_map_t> > >
BlobMap::end() const {
  return boost::make_zip_iterator(boost::make_tuple(kend(), vend()));
}

// find if ``key'' is in the blobmap
MapKeyIterator<BlobMap::graph_map_t>
BlobMap::find(graph_key_type const &key) const {
  return graphs_.find(key);
}

// number of graphs stored in the blobmap
size_t BlobMap::size() const { return graphs_.size(); }

// fetches the graph associated to ``key'' into the cache and build it
// there can be only one graph in the cache
void BlobMap::fetch_(graph_key_type const &key) const {
}

namespace {
struct FirstKeyComparator {
  template <class T> int operator()(T const &lhs, T const &rhs) const {
    return lhs.first < rhs.first;
  }
};
}

// get the most recent key in the blobmap
BlobMap::graph_key_type const &BlobMap::back_key() const {
  graph_map_t::const_iterator imax =
      std::max_element(graphs_.begin(), graphs_.end(), FirstKeyComparator());
  if (imax == graphs_.end()) {
    throw std::runtime_error("no graph available");
  }
  return imax->first;
}

// get the Graph associated to ``key''
Graph const &BlobMap::operator[](graph_key_type const &key) const {
  fetch_(key);
  graph_map_t::const_iterator where = graphs_.find(key);
  return *where->second;
}

Graph &BlobMap::operator[](graph_key_type const &key) {
  fetch_(key);
  graph_map_t::iterator where = graphs_.find(key);
  return *where->second;
}
