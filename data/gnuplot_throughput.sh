# Set output type
set terminal pngcairo  transparent enhanced font "arial,10" fontscale 1.0 size 500, 350
set output 'output_throughput.png'

# Set title of column outside the box
# set key invert reverse Left outside
set key Left outside

# Set title
set title "Throughput Comparision" font ",18"

# Set type of box
set boxwidth 0.8 absolute
set style data histogram
set style histogram cluster gap 1
set style fill pattern border

# Set label
set xlabel "Number of nodes" font ",16"
set ylabel "Throughput (Mbps)" font ",16"

set auto x
set yrange [0:*]

# Plot the data
plot 'data_throughput.dat' using 2:xtic(1) title col, \
        '' using 3:xtic(1) title col, \
        '' using 4:xtic(1) title col, \
#        '' using 5:xtic(1) title col, \
#        '' using 6:xtic(1) title col