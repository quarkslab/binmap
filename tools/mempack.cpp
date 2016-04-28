#include <iostream>
#include <iterator>
#include <iomanip>
#include <fstream>

static void xxd(std::istream & in, std::ostream & out) {
    out << std::hex << std::showbase;
    unsigned char c;
    in >> std::noskipws;
    in >> c;
    if(in)
        out << (int)c;
    while(in) {
        in >> c;
        if(in)
            out << ',' << (int)c;

    }
}

int main(int argc, char* argv[]) {
    if(argc < 2 || argc > 3)
        return 1;
    std::ifstream input(argv[1], std::ios::binary);
    if(argc == 2)
        xxd(input, std::cout);
    else {
        std::ofstream output(argv[2]);
        xxd(input, output);
    }
    return 0;
}
