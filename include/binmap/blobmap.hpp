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

#ifndef BINMAP_BLOBMAP_HPP
#define BINMAP_BLOBMAP_HPP

#include "graph.hpp"
#include "metadata.hpp"

#include <boost/shared_ptr.hpp>
#include <boost/iterator/zip_iterator.hpp>

#include <ciso646>

template <class G> struct KeyIterator {
  G const &graph_;
  typename G::vertex_iterator iter_;

  typedef boost::filesystem::path reference;
  typedef boost::filesystem::path value_type;
  typedef typename G::vertex_iterator::iterator_category iterator_category;
  typedef typename G::vertex_iterator::difference_type difference_type;
  typedef typename G::vertex_iterator::pointer pointer;

  KeyIterator(G const &graph, typename G::vertex_iterator v)
      : graph_(graph), iter_(v) {}

  reference operator*() const { return graph_.key(*iter_); }
  KeyIterator &operator++() {
    ++iter_;
    return *this;
  }
  KeyIterator operator++(int) {
    KeyIterator other(*this);
    ++(*this);
    return other;
  }
  bool operator==(KeyIterator const &other) const {
    return iter_ == other.iter_;
  }
};

template <class G> struct MetadataIterator {
  G const &graph_;
  boost::shared_ptr<Metadata const> metadata_;
  typename G::vertex_iterator iter_;

  typedef MetadataInfo reference;
  typedef MetadataInfo value_type;
  typedef typename G::vertex_iterator::iterator_category iterator_category;
  typedef typename G::vertex_iterator::difference_type difference_type;
  typedef typename G::vertex_iterator::pointer pointer;

  MetadataIterator(G const &graph, typename G::vertex_iterator v,
                   boost::shared_ptr<Metadata const> const &md)
      : graph_(graph), metadata_(md), iter_(v) {}

  MetadataInfo operator*() const { return (*metadata_)[graph_.hash(*iter_)]; }
  MetadataIterator &operator++() {
    ++iter_;
    return *this;
  }
  MetadataIterator operator++(int) {
    MetadataIterator other(*this);
    ++(*this);
    return other;
  }
  bool operator==(MetadataIterator const &other) const {
    return iter_ == other.iter_;
  }
};

struct NodeDiff {
  std::pair<MetadataInfo, MetadataInfo> mdis;
  std::pair<boost::unordered_set<boost::filesystem::path>,
            boost::unordered_set<boost::filesystem::path> > deps;

  bool empty() const;
};

std::ostream &operator<<(std::ostream &os, NodeDiff const &nd);

struct BlobMapDiff {

  std::map<boost::filesystem::path, NodeDiff> updated;
  boost::unordered_set<boost::filesystem::path> added_nodes;
  boost::unordered_set<boost::filesystem::path> removed_nodes;

  BlobMapDiff();
};

class BlobMapView {
  boost::shared_ptr<Metadata const> metadata_;
  Graph graph_;

public:
  BlobMapView(boost::shared_ptr<Metadata const> const &metadata,
              Graph const &graph = Graph());

  boost::shared_ptr<Metadata const> const &metadata() const;

  Graph const &graph() const;

  void graph(Graph const &graph);

  MetadataIterator<Graph> vbegin() const;
  MetadataIterator<Graph> vend() const;

  KeyIterator<Graph> kbegin() const;
  KeyIterator<Graph> kend() const;

  boost::zip_iterator<
      boost::tuple<KeyIterator<Graph>, MetadataIterator<Graph> > >
  begin() const;
  boost::zip_iterator<
      boost::tuple<KeyIterator<Graph>, MetadataIterator<Graph> > >
  end() const;

  MetadataInfo operator[](boost::filesystem::path const &filename) const;

  bool has_path(boost::filesystem::path const &from,
                boost::filesystem::path const &to) const;

  void successors(Graph::successors_type &succs,
                  boost::filesystem::path const &key) const;
  void predecessors(Graph::successors_type &preds,
                    boost::filesystem::path const &key) const;

  void induced_graph(BlobMapView &pred,
                     boost::filesystem::path const &key) const;
  void induced_successors(BlobMapView &succ,
                          boost::filesystem::path const &key) const;
  void induced_predecessors(BlobMapView &pred,
                            boost::filesystem::path const &key) const;

  template <class F> void filter(F filter, BlobMapView &out) const {
    Graph &ograph = out.graph_;
    Graph::const_hashes_t hashes = graph_.hashes();

    /* populate */
    for (Graph::vertex_iterator iter = graph_.begin(), end = graph_.end();
         iter != end; ++iter) {
      Hash const &hash = hashes[*iter];
      MetadataInfo const &md = (*metadata_)[hash];
      boost::filesystem::path const &key = graph_.key(*iter);
      if (filter(key, md, *this) and not ograph.has_node(key)) {
        ograph.add_node(key, hash);
        for (Graph::edge_iterator viter = graph_.edge_begin(*iter),
                                  vend = graph_.edge_end(*iter);
             viter != vend; ++viter) {
          Graph::vertex_descriptor v = boost::target(*viter, graph_.graph());
          Hash const &vhash = hashes[v];
          MetadataInfo const &vmd = (*metadata_)[vhash];
          boost::filesystem::path const &vkey = graph_.key(v);
          if (filter(vkey, vmd, *this)) { // FIXME could be memoized
            if (not ograph.has_node(vkey))
              ograph.add_node(vkey, vhash);
            ograph.add_edge(key, vkey);
          }
        }
      }
    }
  }

  template <class P>
  void project(P project,
               GraphProjection<typename P::result_type> &ograph) const {

    Graph::const_hashes_t hashes = graph_.hashes();

    /* populate */
    for (Graph::vertex_iterator iter = graph_.begin(), end = graph_.end();
         iter != end; ++iter) {
      Hash const &hash = hashes[*iter];
      MetadataInfo const &md = (*metadata_)[hash];
      typename P::result_type const &key = project(md);
      if (not ograph.has_node(key)) {
        ograph.add_node(key);
      }
    }

    /* add edges */
    for (Graph::vertex_iterator iter = graph_.begin(), end = graph_.end();
         iter != end; ++iter) {
      Hash const &hash = hashes[*iter];
      MetadataInfo const &md = (*metadata_)[hash];
      typename P::result_type const &key = project(md);

      for (Graph::edge_iterator viter = graph_.edge_begin(*iter),
                                vend = graph_.edge_end(*iter);
           viter != vend; ++viter) {
        Graph::vertex_descriptor v = boost::target(*viter, graph_.graph());
        Hash const &vhash = hashes[v];
        MetadataInfo const &vmd = (*metadata_)[vhash];
        typename P::result_type const &vkey =
            project(vmd); // FIXME potentially costly, could be memoized
        ograph.add_edge(key, vkey);
      }
    }
  }

  void dot(boost::filesystem::path const &path) const;
  void json(std::string &out) const;

  void diff(BlobMapDiff &diff, BlobMapView const &other) const;

  size_t size() const;
};

template <class M> struct MapKeyIterator {
  typedef typename std::iterator_traits<
      typename M::const_iterator>::value_type::first_type &reference;
  typedef typename std::iterator_traits<
      typename M::const_iterator>::value_type::first_type value_type;
  typedef typename std::iterator_traits<
      typename M::const_iterator>::iterator_category iterator_category;
  typedef typename std::iterator_traits<
      typename M::const_iterator>::difference_type difference_type;
  typedef typename std::iterator_traits<typename M::const_iterator>::pointer
  pointer;

  typename M::const_iterator iter_;

  MapKeyIterator(typename M::const_iterator iter) : iter_(iter) {}

  reference operator*() const { return iter_->first; }
  MapKeyIterator<M> &operator++() {
    ++iter_;
    return *this;
  }
  MapKeyIterator<M> operator++(int) {
    MapKeyIterator<M> other(*this);
    ++(*this);
    return other;
  }
  bool operator==(MapKeyIterator const &other) const {
    return iter_ == other.iter_;
  }
  bool operator!=(MapKeyIterator const &other) const {
    return iter_ != other.iter_;
  }
};
template <class M> struct MapValueIterator {
  typedef BlobMapView reference;
  typedef BlobMapView value_type;
  typedef typename std::iterator_traits<
      typename M::const_iterator>::iterator_category iterator_category;
  typedef typename std::iterator_traits<
      typename M::const_iterator>::difference_type difference_type;
  typedef typename std::iterator_traits<typename M::const_iterator>::pointer
  pointer;

  boost::shared_ptr<Metadata const> metadata_;
  typename M::const_iterator iter_;

  MapValueIterator(boost::shared_ptr<Metadata const> const &metadata,
                   typename M::const_iterator iter)
      : metadata_(metadata), iter_(iter) {}

  reference operator*() const { return BlobMapView(metadata_, *iter_->second); }
  MapValueIterator<M> &operator++() {
    ++iter_;
    return *this;
  }
  MapValueIterator<M> operator++(int) {
    MapValueIterator<M> other(*this);
    ++(*this);
    return other;
  }
  bool operator==(MapValueIterator const &other) const {
    return iter_ == other.iter_;
  }
  bool operator!=(MapValueIterator const &other) const {
    return iter_ != other.iter_;
  }
};

class BlobMap {
public:
  typedef time_t graph_key_type;
  typedef std::map<graph_key_type, Graph *> graph_map_t;

private:
  graph_map_t graphs_;
  boost::shared_ptr<Metadata> metadata_;

public:
  BlobMap();
  BlobMap(boost::filesystem::path const &);
  ~BlobMap();

  boost::shared_ptr<Metadata const> metadata() const;

  boost::shared_ptr<Metadata> metadata();

  bool empty() const;

  Graph &create(graph_key_type const &key);

  void store(boost::filesystem::path const &archive_path);

  graph_key_type const &back_key() const;
  Graph const &operator[](graph_key_type const &key) const;
  Graph &operator[](graph_key_type const &key);

  void back(BlobMapView &bmv) const;
  void at(BlobMapView &bmv, graph_key_type const &key) const;

  MapKeyIterator<graph_map_t> kbegin() const;
  MapKeyIterator<graph_map_t> kend() const;
  MapValueIterator<graph_map_t> vbegin() const;
  MapValueIterator<graph_map_t> vend() const;
  boost::zip_iterator<boost::tuple<MapKeyIterator<graph_map_t>,
                                   MapValueIterator<graph_map_t> > >
  begin() const;
  boost::zip_iterator<boost::tuple<MapKeyIterator<graph_map_t>,
                                   MapValueIterator<graph_map_t> > >
  end() const;

  MapKeyIterator<graph_map_t> find(graph_key_type const &key) const;

  size_t size() const;

  template < class Archive >
  void serialize(Archive & ar, unsigned int) {
      ar & graphs_;
      ar& *metadata_;
  }

protected:
  void fetch_(graph_key_type const &) const;
};

#endif
