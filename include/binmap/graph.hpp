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

#ifndef BINMAP_GRAPH_HPP
#define BINMAP_GRAPH_HPP

#include "binmap/hash.hpp"

#include <string>
#include <boost/unordered_map.hpp>
#include <boost/unordered_set.hpp>

#include <boost/graph/graph_traits.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/graphviz.hpp>

#include <boost/graph/adj_list_serialize.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/map.hpp>
#include "boost_ex/filesystem/serialization.hpp"
#include "boost_ex/serialization/unordered_map.hpp"
#include "boost_ex/serialization/unordered_set.hpp"

/* define a new graph property to hold the hash of a node */
namespace boost {
enum vertex_hash_t {
  vertex_hash
};
BOOST_INSTALL_PROPERTY(vertex, hash);
}

class Graph {

  typedef boost::property<boost::vertex_name_t, boost::filesystem::path,
                          boost::property<boost::vertex_hash_t, Hash> >
  vertex_property;
  typedef boost::adjacency_list<boost::vecS, boost::vecS, boost::bidirectionalS,
                                vertex_property> graph_type;

  graph_type graph_;
  boost::unordered_map<boost::filesystem::path, graph_type::vertex_descriptor>
  mapping_;
  mutable std::vector<int> *distance_matrix_;

  boost::unordered_map<boost::filesystem::path, int> passed_path_;
  boost::unordered_map<boost::filesystem::path, graph_type::vertex_descriptor>::iterator
	map_p_;

public:
  Graph();
  ~Graph();

  typedef boost::unordered_set<boost::filesystem::path> successors_type;
  typedef boost::property_map<graph_type, boost::vertex_hash_t>::const_type
  const_hashes_t;
  typedef boost::graph_traits<graph_type>::vertex_iterator vertex_iterator;
  typedef vertex_iterator iterator;
  typedef graph_type::vertex_descriptor vertex_descriptor;
  typedef boost::graph_traits<graph_type>::out_edge_iterator edge_iterator;

  bool has_node(boost::filesystem::path const &path) const;

  bool has_path(boost::filesystem::path const &from,
                boost::filesystem::path const &to) const;

  boost::filesystem::path add_node(boost::filesystem::path const &input_file,
                Hash const &input_hash);

  graph_type const &graph() const;

  /** get the filename associated to a node descriptor */
  boost::filesystem::path const &key(graph_type::vertex_descriptor vd) const;

  /** get the hash associated to a node descriptor */
  Hash const &hash(graph_type::vertex_descriptor vd) const;

  /** get the hash associated to a filename */
  Hash const &hash(boost::filesystem::path const &key) const;

  /** collects all successors of a filename in succs */
  void successors(successors_type &succs,
                  boost::filesystem::path const &key) const;
  void predecessors(successors_type &preds,
                    boost::filesystem::path const &key) const;

  /** get internal filename to hash dict */
  const_hashes_t hashes() const;

  /** iterates over vertices */
  vertex_iterator begin() const;

  vertex_iterator end() const;

  /** iterates over successors of a node */
  edge_iterator edge_begin(boost::filesystem::path const &input_file) const;

  edge_iterator edge_end(boost::filesystem::path const &input_file) const;

  edge_iterator edge_begin(graph_type::vertex_descriptor input) const;

  edge_iterator edge_end(graph_type::vertex_descriptor input) const;

  /** add edge between from and to, pointing toward to*/
  void add_edge(boost::filesystem::path const &from,
                boost::filesystem::path const &to);

  /** dump the graph as a .dot file */
  void dot(boost::filesystem::path const &path) const;

  size_t size() const;

  template < class Archive >
  void serialize(Archive & ar, unsigned int) {
      ar& graph_ & mapping_;
  }

protected:
  void compute_distance_matrix() const;
};

/** Class resulting from the projection of a graph to a new dimension */

template <class T> class GraphProjection {

  typedef boost::property<boost::vertex_name_t, T> vertex_property;
  typedef boost::adjacency_list<boost::vecS, boost::vecS, boost::directedS,
                                vertex_property> graph_type;

  graph_type graph_;
  boost::unordered_map<T, typename graph_type::vertex_descriptor> mapping_;

/**********************AJOUTE PAR MOI***************/
  boost::unordered_map<T, typename boost::filesystem::path> passed_path_;

public:
  typedef typename boost::graph_traits<graph_type>::vertex_iterator
  vertex_iterator;
  bool has_node(T const &key) const {
    return mapping_.find(key) != mapping_.end();
  }

  boost::filesystem::path add_node(T const &key) {
    assert(not has_node(key));
    typename graph_type::vertex_descriptor v = boost::add_vertex(graph_);
    mapping_[key] = v;

    boost::put(boost::vertex_name_t(), graph_, v, key);
  }

  vertex_iterator begin() const { return boost::vertices(graph_).first; }
  vertex_iterator end() const { return boost::vertices(graph_).second; }

  void add_edge(T const &from, T const &to) {
    assert(has_node(from));
    assert(has_node(to));
    boost::add_edge(mapping_[from], mapping_[to], graph_);
  }
  void dot(boost::filesystem::path const &path) const {
    std::ofstream dotfile(path.c_str());
    boost::write_graphviz(
        dotfile, graph_,
        boost::make_label_writer(boost::get(boost::vertex_name_t(), graph_)));
  }
};

#endif
