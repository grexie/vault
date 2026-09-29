// Generates deployable app icons from the original rendered terminal artwork.
package main

import (
	"fmt"
	"golang.org/x/image/draw"
	"image"
	"image/png"
	"os"
)

func main() {
	input, err := os.Open("assets/terminal-icon.png")
	if err != nil {
		panic(err)
	}
	source, err := png.Decode(input)
	input.Close()
	if err != nil {
		panic(err)
	}
	for _, n := range []int{32, 180, 192, 512} {
		out := image.NewRGBA(image.Rect(0, 0, n, n))
		draw.CatmullRom.Scale(out, out.Bounds(), source, source.Bounds(), draw.Src, nil)
		name := fmt.Sprintf("web/static/icon-%d.png", n)
		if n == 32 {
			name = "web/static/favicon-32.png"
		}
		file, err := os.Create(name)
		if err != nil {
			panic(err)
		}
		if err = png.Encode(file, out); err != nil {
			panic(err)
		}
		if err = file.Close(); err != nil {
			panic(err)
		}
	}
}
