set terminal pngcairo  transparent enhanced font "arial,10" fontscale 1.0 size 500, 400
set output 'output_decryption.png'

# Set key legend (box label)
# set key invert reverse Left outside
set key font ",12"
set key inside left top

# Set title
set title "Decryption comparison" font ",18"

# Set type of box
set boxwidth 0.8 absolute
set style data histogram
set style histogram cluster gap 1
set style fill pattern border

# Set label
set xlabel "Text length (# of character)" font ",16"
set ylabel "Time (ms)" font ",16"

#set auto x
#set yrange [0:*]

# Plot the data
plot 'data_decryption.dat' using 2:xtic(1) title col, \
        '' using 3:xtic(1) title col, \
#        '' using 4:xtic(1) title col, \
#        '' using 5:xtic(1) title col, \
#        '' using 6:xtic(1) title col





