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

/* CLI Front end to the binmap internals
 *
 * handles command line option parsing and dispatching
 */
#include "binmap_config.hpp"
#include "binmap/log.hpp"
#include "binmap/scan.hpp"
#include "binmap/view.hpp"

#include <iostream>
#include <sstream>
#include <fstream>

#include <boost/program_options.hpp>
#include <boost/foreach.hpp>
#include <boost/filesystem/operations.hpp>

#define DEFAULT_BLOBS "blobs.dat"
#define DEFAULT_DOT "blobs.dot"

namespace po = boost::program_options;

/** Generic Command class that handles boost::program_options boilerplate*/
class Command {

protected:
  std::string cmd_name_;

  po::options_description desc_;
  po::options_description positional_;
  po::positional_options_description positional_opts_;
  po::variables_map vm_;

  /** override this to define option handling behavior*/
  virtual int process() = 0;

public:
  /** construct a new named command */
  Command(std::string const &name) : cmd_name_(name), desc_("options") {
    desc_.add_options()("help,h",
                        ("print " + cmd_name_ + " help and exit").c_str());
  }

  virtual ~Command() {}

  /** retrieve command name */
  std::string const &name() const { return cmd_name_; }

  /** process arguments according to option description */
  int run(int argc, char *argv[]) {
    po::options_description all_opts;
    all_opts.add(desc_).add(positional_);
    po::store(po::command_line_parser(argc, argv)
                  .options(all_opts)
                  .positional(positional_opts_)
                  .run(),
              vm_);
    po::notify(vm_);
    if (vm_.count("help")) {
      std::cout << cmd_name_ << " [options]";
      if (positional_opts_.max_total_count() != 0)
        std::cout << " " << positional_opts_.name_for_position(0);
      if (positional_opts_.max_total_count() > 1)
        std::cout << "...";
      std::cout << std::endl << desc_;
      return 0;
    }
    return process();
  }
};

/** Command that dispatches sub commands*/
class MainCommand : public Command {

  std::vector<Command *> subcmds_;

  /* process default options not specific to a subcommand*/
  int process() {
    if (vm_.count("help")) {
      std::cout << usage() << desc_ << std::endl;
      return 0;
    }
    if (vm_.count("version")) {
      std::cout << "binmap " << BINMAP_VERSION << std::endl;
      return 0;
    }
    return 1;
  }

public:
  MainCommand() : Command("binmap") {
    desc_.add_options()("version", "print version and exit");
  }

  /** help */
  std::string usage() {
    std::ostringstream oss;
    oss << "binmap - a system dependency analyzer" << std::endl
        << "Usage: binmap [--help|--version]" << std::endl;
    BOOST_FOREACH(Command* subcmd, subcmds_) {
      oss << "       binmap " << subcmd->name() << " [options]" << std::endl;
    }
    return oss.str();
  }

  /** overrides default behavior, only call this if there is no subcommand*/
  int run(int argc, char *argv[]) {
    po::store(po::command_line_parser(argc, argv)
                  .options(desc_)
                  .positional(positional_opts_)
                  .run(),
              vm_);
    po::notify(vm_);
    return process();
  }

  /* command dispatcher */
  int run_subcmd(std::string const &cmd, int argc, char *argv[]) {
    for (std::vector<Command *>::iterator iter = subcmds_.begin();
         iter != subcmds_.end(); ++iter)
      if ((*iter)->name() == cmd) {
        return (*iter)->run(argc, argv);
      }
    std::cerr << "unknown sub command: `" << cmd << "'" << std::endl;
    return 1;
  }

  /** add a subcommand */
  void register_subcmd(Command *cmd) { subcmds_.push_back(cmd); }
};

/** Generic class to hold a subcommand, inherit from this to define a new
 * Subcommand*/
class SubCommand : public Command {
public:
  /** Constructor provides an automatic registration of a subcommand */
  SubCommand(MainCommand &mcmd, std::string const &name) : Command(name) {
    mcmd.register_subcmd(this);
  }
};

struct canonicalize_path {

  void operator()(boost::filesystem::path &path) const {
    path = boost::filesystem::canonical(path, ".");
  }
};

/* Implement Scanning options */
class ScanCommand : public SubCommand {

  int process() {

    logging::log.set(logging::verbosity_level(vm_["verbose"].as<int>()));

    std::vector<std::string> str_inputs;
    std::vector<boost::filesystem::path> inputs;
    if (vm_.count("inputs") == 0)
      throw po::required_option("inputs");
    else {
      str_inputs = vm_["inputs"].as<std::vector<std::string> >();
      std::copy(str_inputs.begin(), str_inputs.end(), std::back_inserter(inputs));
      std::for_each(inputs.begin(), inputs.end(), canonicalize_path());
    }

    std::vector<boost::filesystem::path> blacklist;
    if (vm_.count("exclude") != 0)
      blacklist = vm_["exclude"].as<std::vector<boost::filesystem::path> >();
    std::for_each(blacklist.begin(), blacklist.end(), canonicalize_path());

    boost::filesystem::path output;
    if (vm_.count("output") != 0)
      output = vm_["output"].as<boost::filesystem::path>();
    else
      output = DEFAULT_BLOBS;

    boost::filesystem::path root;
    if (vm_.count("chroot") != 0) {
      root = inputs[0];
      // if more than one input is given, scan the whole system
      if(inputs.size() > 1) {
        std::copy(inputs.begin() + 1, inputs.end(), inputs.begin());
        inputs.pop_back();
      }
      // otherwise, keep inputs[0] as it is the sole entry point
    }

    return scan(inputs, output, root, blacklist);
  }

public:
  ScanCommand(MainCommand &mcmd) : SubCommand(mcmd, "scan") {
    positional_.add_options()("inputs", po::value<std::vector<std::string> >(), "");
    positional_opts_.add("inputs", -1);
    desc_.add_options()
      ("output,o", po::value<boost::filesystem::path>(), "output path [default=" DEFAULT_BLOBS "]")
      ("chroot", "target is the image of another system")
      ("exclude", po::value<std::vector<boost::filesystem::path> >(), "exclude given paths from the scan")
      ("verbose,v", po::value<int>()->default_value(logging::error), "verbosity level");

    std::ifstream config_file(".binmap.cfg");
    if (config_file) {
      try {
        po::store(po::parse_config_file(config_file, desc_), vm_);
        vm_.notify();
      }
      catch (boost::program_options::error const &e) {
        logging::log(logging::error) << "in configuration file: " << e.what() << std::endl;
      }
    }
  }
};

#if BINMAP_FULL

/* Implement dump to dot options */
class ViewCommand : public SubCommand {

  int process() {
    return view(
        vm_.count("input") != 0 ? vm_["input"].as<boost::filesystem::path>()
                                : boost::filesystem::path(DEFAULT_BLOBS),
        vm_.count("output") != 0 ? vm_["output"].as<boost::filesystem::path>()
                                 : boost::filesystem::path(DEFAULT_DOT));
  }

public:
  ViewCommand(MainCommand &mcmd) : SubCommand(mcmd, "view") {
    desc_.add_options()("input,i", po::value<boost::filesystem::path>(),
                        "input path [default=" DEFAULT_BLOBS "]");
    desc_.add_options()("output,o", po::value<boost::filesystem::path>(),
                        "output path [default=" DEFAULT_DOT "]");
  }
};

#endif

int main(int argc, char *argv[]) {
  MainCommand cmd;
  ScanCommand sccmd(cmd);
#if BINMAP_FULL
  ViewCommand shcmd(cmd);
#endif

  if (argc == 1) {
    std::cerr << cmd.usage();
    return 1;
  } else {
    /* if first option starts with a dash, it's not a sub command */
    if (argv[1][0] == '-')
      return cmd.run(argc, argv);
    else {
      /* fool program_options by removing the subcommand name */
      try {
        char const *subcommand = argv[1];
        memmove(argv + 1, argv + 2, (argc - 1) * sizeof(*argv));
        return cmd.run_subcmd(subcommand, argc - 1, argv);
      }
      catch (boost::program_options::error const &e) {
        std::cerr << e.what() << std::endl;
        return 1;
      }
    }
  }
}
