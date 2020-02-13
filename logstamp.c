#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
	bool utc;
	char *format = "%b %e %T"; /* like syslog */
	char *sep = " ";
	int ch;
	while ((ch = getopt(argc, argv, "uf:s:?")) != -1)
		switch (ch) {
		case 'u':
			utc = true;
			break;
		case 'f':
			format = optarg;
			break;
		case 's':
			sep = optarg;
			break;
		case '?':
			fprintf(stderr, "usage: %s [-u] [-f strftime] [-s separator] [file ...]\n", getprogname());
			exit(EX_USAGE);
		}
	argc -= optind, argv += optind;

	do {
		FILE *file;
		const char *file_name;
		if (argc) {
			file = fopen((file_name = *argv), "r");
			if (!file)
				err(EX_NOINPUT, "%s", *argv);
			argc--, argv++;
		} else {
			file = stdin;
			file_name = "stdin";
		}

		char stamp[128];
		time_t stamp_last_time = -1;
		char *line;
		size_t line_len;
		while ((line = fgetln(file, &line_len))) {
			if (*format) {
				time_t now;
				struct tm *tm;
				size_t n;
				time(&now);
				if (now != stamp_last_time) {
					if (utc)
						tm = gmtime(&now);
					else
						tm = localtime(&now);
					if (!tm)
						err(EX_TEMPFAIL, "gmtime/localtime");
					n = strftime(stamp, sizeof stamp, format, tm);
					if (!n)
						err(EX_DATAERR, "strftime");
					stamp_last_time = now;
				}
				fputs(stamp, stdout);
			}
			fputs(sep, stdout);
			fwrite(line, 1, line_len, stdout);
			fflush(stdout); /* this is where the slow come from */
			if (ferror(stdout))
				err(EX_IOERR, "stdout");
		}
		if (ferror(file))
			err(EX_IOERR, "file");
	} while (argc);

	return EX_OK;
}
