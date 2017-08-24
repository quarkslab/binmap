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

#include "binmap/scan.hpp"
#include "binmap/blobmap.hpp"

#include "binmap/log.hpp"
#include "binmap/hash.hpp"
#include "binmap/env.hpp"

#include "binmap/collector.hpp"

#include <vector>
#include <set>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <fstream>

#include <cassert>
#include <cstdio>

#include <boost/foreach.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>

#include <boost/archive/text_oarchive.hpp>

class Scanner {

  BlobMap blobmap_;
  time_t now_;
  boost::unordered_set<boost::filesystem::path> visited_;

  Scanner(Scanner const &);

public:
  Scanner(boost::filesystem::path const &archive_path,
          std::vector<boost::filesystem::path> const &blacklist =
              std::vector<boost::filesystem::path>())
      : blobmap_(archive_path), now_(0), visited_(blacklist.begin(), blacklist.end()) {
  }

  BlobMap const &blobmap() { return blobmap_; }

  bool operator()(boost::filesystem::path const &input_file) {
    Graph &graph = current_graph();
    if (visited_.find(input_file) == visited_.end()) {

      visited_.insert(input_file);

      if (boost::filesystem::is_directory(input_file)) {
        /* avoid infinite recursion */
        if (boost::filesystem::is_symlink(input_file)) {
          std::set<boost::filesystem::path> deps;
          std::auto_ptr<Collector> collector =
              Collector::get_collector(input_file);
          if (collector.get()) {
            (*collector)(deps);
            if (deps.size() == 0)
              assert(deps.size() == 1);
            (*this)(*deps.begin());
          }
        }
        /* recurse through directories */
        else {
          logging::log(logging::info) << "walking directory: " << input_file
                                      << std::endl;
          boost::system::error_code ec;
          std::vector<boost::filesystem::path> children;
          for (boost::filesystem::directory_iterator node(input_file, ec), end;
               node != end; node.increment(ec)) {
            if (not ec)
              children.push_back(node->path());
          }
          BOOST_FOREACH(boost::filesystem::path const & child, children) {
            if(! (*this)(child) )
            {
              logging::log(logging::warning) << "skipping entry '"
                                             << child.string()
                                             << std::endl; // TODO: native() vs.
                                                           // string on windows
            }
          }
        }
      } else if (boost::filesystem::is_other(input_file)) {
        logging::log(logging::warning) << "skipping special file: " << input_file
                                       << std::endl;
        /* just skip */
      }
      /* analyse file */
      else {
        std::auto_ptr<Collector> collector = Collector::get_collector(input_file);
        if (collector.get()) {
          Hash input_hash(input_file);

          boost::filesystem::path path_to_add = add_node(input_file, input_hash);

	  if (path_to_add == input_file || visited_.find(path_to_add) == visited_.end()) {
		visited_.insert(path_to_add);

		std::set<boost::filesystem::path> deps;
		try {
			logging::log(logging::info) << "analysing file: " << path_to_add << " "
						<< input_hash << std::endl;
			analyze_dependencies(*collector, deps);
			analyze_metadata(*collector, input_hash);
			add_deps(path_to_add, deps);
			logging::log(logging::info) << " done for " << path_to_add <<"\n" << std::endl;
		}
		catch (std::exception const &e) {
			// this happen when the collector is_valid returns true but raises an
			// error during its processing
			logging::log(logging::warning) << "bad format: skipping "
						   << input_file
						   << " (error was:" << e.what()
						   << std::endl;
			// still write dummy metadata for consistency
			blobmap_.metadata()->insert(MetadataInfo(input_hash));
		}
	  }

        } else {
          logging::log(logging::warning) << "skipping unhandled file: "
                                         << input_file << std::endl;
          return false;
        }
      }
    } else if (not graph.has_node(trim_root(input_file))) {
      // the node has already been visited, but for some reason, it has not been
      // registered
      // most probably it was faulty
      // so rethrow exception
    }
    return true;
  }

private:
  Graph const &current_graph() const {
    if (now_ == 0) {
      throw std::runtime_error("no generated graph");
    }
    return blobmap_[now_];
  }

  Graph &current_graph() {
    if (now_ == 0) {
      do {
        now_ = time(0);
        // wait at most 1 sec
      } while (blobmap_.find(now_) != blobmap_.kend());
      blobmap_.create(now_);
    }
    return blobmap_[now_];
  }

  template<class Iterable>
  void analyze_dependencies(Collector &collector, Iterable &deps) {
    std::set<boost::filesystem::path> temp_deps;
    collector(temp_deps);
    BOOST_FOREACH(boost::filesystem::path const& dep, temp_deps) {
      (*this)(dep);
      deps.insert(dep);
    }
  }

  void analyze_metadata(Collector &collector,
                        Hash const &input_hash) {
    try {    
      MetadataInfo mi(input_hash);
      collector(mi);
      blobmap_.metadata()->insert(mi);
    }
    catch (...) {
      /* should log something */
    }
  }

  boost::filesystem::path
  add_node(boost::filesystem::path const &input_file,
                            Hash const &input_hash) {
    //logging::log(logging::warning) << "\nadding file: " << input_file<<"\n";
    boost::filesystem::path const trimed_input_file = trim_root(input_file);
    Graph &graph = current_graph();
    boost::filesystem::path to_add = graph.add_node(trimed_input_file, input_hash);
    logging::log(logging::warning) << "\nadding file: " << to_add << " "
                                << input_hash <<""<< std::endl;
    return to_add;
  }

  template<class Iterable>
  void
  add_deps(boost::filesystem::path const &input_file,
                            Iterable const &deps) {
    boost::filesystem::path const trimed_input_file = trim_root(input_file);
    Graph &graph = current_graph();

    BOOST_FOREACH(typename Iterable::value_type const& dep, deps) {
      graph.add_edge(trimed_input_file, trim_root(dep));
    }
    logging::log(logging::info) << "adding deps of: " << trimed_input_file << std::endl;
  }

  boost::filesystem::path trim_root(boost::filesystem::path const &path) const {
    //TODO: fix for windows native() vs. string()
    std::string const& root = Env::root().string();
    std::string dll_name = path.filename().string();

    boost::algorithm::to_lower(dll_name);
    boost::filesystem::path path_low = (path.parent_path() / dll_name);
    
    std::string const& spath = path_low.string();
    // only trim root if root is a prefix
    //std::cout << "\nspath: " << spath << " root: " << root << " path " << path << "\n";
    if (root.size() < spath.size()
        and std::equal(root.begin(), root.end(), spath.begin()))
      return spath.c_str() + Env::root().string().size();
    // root is not a prefix for unresolved filenames
    else
      return spath;
  }
};

namespace {
void print_blacklist(boost::filesystem::path const& item) {
    logging::log(logging::info) << "blacklisting: " << item << std::endl;
}
}

int scan(std::vector<boost::filesystem::path> const &paths,
         boost::filesystem::path const &output_path,
         boost::filesystem::path const &root,
         std::vector<boost::filesystem::path> blacklist/*make a copy for inplace modification*/)
{
  blacklist.push_back("/dev");
  blacklist.push_back("/proc");
  blacklist.push_back("/sys");
  blacklist.push_back("/tmp");

  std::for_each(blacklist.begin(), blacklist.end(), print_blacklist);

  Scanner scanner(output_path, blacklist);
  Env::initialize_all(root);

  BOOST_FOREACH(boost::filesystem::path const & path, paths) {
    try {
      scanner(path);
    }
    catch (...) {
    }
  }

  std::ofstream ofs(output_path.string().c_str(), std::ios::binary);
  boost::archive::text_oarchive oa(ofs);
  oa& scanner.blobmap();
  return 0;
}
