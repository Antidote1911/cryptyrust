cargo update
cargo +nightly build --release
cd gui
qmake cryptyrust.pro
make
