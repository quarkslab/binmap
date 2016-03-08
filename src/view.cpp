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

#include "binmap/view.hpp"
#include "binmap/blobmap.hpp"
#include "binmap/log.hpp"

#include <boost/filesystem/operations.hpp>

int view(boost::filesystem::path const &archive_path,
         boost::filesystem::path const &dot_path)
{
  if (boost::filesystem::exists(archive_path)) {
    BlobMap bm(archive_path);
    BlobMapView bmv(bm.metadata());
    bm.back(bmv);
    bmv.dot(dot_path);
    return 0;
  } else {
    logging::log(logging::error) << "input not found: " << archive_path
                                 << std::endl;
    return 1;
  }
}
