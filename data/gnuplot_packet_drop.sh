#reset
set terminal png
set output 'output_packet_drop.png'

set xlabel "Number of node"
set xrange [25:100]
set xtics 25,25,100

set ylabel "Packet drop ratio"

set title "Packet Drop Ratio"
set key inside left top
set grid

set style data linespoints

#plot "data_throughput.dat" using 1:3 title "slot 1", \
#"" using 1:4 title "slot 2", \
#"" using 1:5 title "slot 3", \
#"" using 1:6 title "slot 4", \
#"" using 1:7 title "slot 5", \
#"" using 1:8 title "slot 6", \
#"" using 1:9 title "slot 7", \
#"" using 1:10 title "slot 8", \
#"" using 1:11 title "slot 9", \
#"" using 1:12 title "slot 10"
#

plot "data_throughput.dat" using 1:2 title "None", \
"" using 1:3 title "RSA", \
"" using 1:4 title "ElGamal", \
