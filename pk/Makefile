proj = pk

pdf: $(proj).pdf

$(proj).aux: *.tex
	pdflatex -halt-on-error -draftmode $(proj)

$(proj).bbl: $(proj).aux *.bib
	bibtex $(proj)

$(proj).pdf: $(proj).bbl
	pdflatex -halt-on-error -draftmode $(proj)
	pdflatex -halt-on-error $(proj)

clean:
	rm -f $(proj).log
	rm -f $(proj).aux
	rm -f $(proj).dvi
	rm -f $(proj).pdf
	rm -f $(proj).bbl
	rm -f $(proj).blg
	rm -f $(proj).out
