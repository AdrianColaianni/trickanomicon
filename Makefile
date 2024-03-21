build:
	@pandoc -s --toc -c style.css --highlight-style rose-pine.theme trickanomicon.md -o trickanomicon.html
live: build
	@while true; do \
		inotifywait -e modify -rqq .; \
		make build; \
	done

