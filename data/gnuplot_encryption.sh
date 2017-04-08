# Set output type
set terminal pngcairo  transparent enhanced font "arial,10" fontscale 1.0 size 450, 450
set output 'output_encryption.png'

# Set title
set title "Encryption comparison" font ",18"


# Set legend (the label of box)
# set key invert reverse Left outside
set key font ",12"
# set key width -12
# set key height 5
# set key Left outside
set key inside left top

# Set type of box
set boxwidth 0.8 absolute
set style data histogram
set style histogram cluster gap 1
set style fill pattern border

# Set label
set xlabel "Text length (# of character)" font ",16" offset 0,-0.5
set ylabel "Time (ms)" font ",16"

#set auto x
#set yrange [0:*]

# Plot the data
plot 'data_encryption.dat' using 2:xtic(1) title col, \
        '' using 3:xtic(1) title col, \
#        '' using 4:xtic(1) title col, \
#        '' using 5:xtic(1) title col, \
#        '' using 6:xtic(1) title col




