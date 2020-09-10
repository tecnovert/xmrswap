
SOURCE=notes

all: $(SOURCE).tex
	pdflatex $(SOURCE).tex < /dev/null
	biber $(SOURCE) < /dev/null > /dev/null
	biber $(SOURCE) < /dev/null > /dev/null
	pdflatex $(SOURCE).tex < /dev/null > /dev/null
	pdflatex $(SOURCE).tex < /dev/null > /dev/null

clean :
	@rm *.aux || true
	@rm *.bbl || true
	@rm *.bcf || true
	@rm *.blg || true
	@rm *.log || true
	@rm *.out || true
	@rm *.run.xml || true
