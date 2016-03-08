#ifndef BOOST_FILESYSTEM_SERIALIZATION_HPP
#define BOOST_FILESYSTEM_SERIALIZATION_HPP

// MS compatible compilers support #pragma once
#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

#include <boost/config.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/serialization/level.hpp>

namespace boost { namespace serialization {

                      template < class Archive >
                      void serialize(Archive & ar, boost::filesystem::path & p,
                                     const unsigned int version)
                      {
                          std::string s;
                          if(Archive::is_saving::value)
                              s = p.string();
                          ar& boost::serialization::make_nvp("string", s);
                          if(Archive::is_loading::value)
                              p = s;
                      }

                  }}

#endif
