extern "C" void dep();
extern "C" void other_dep();
int main() {
    dep();
    other_dep();
    return 0;
}
