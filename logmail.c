#include <err.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

/* Simple program to monitor an input stream and mail it while respecting
 * certain limits to avoid flooding a mailbox.
 *
 * The size of individual mails is limited and the delay between mails
 * increases exponentially (and is slowly decreased when no mails need to be
 * sent for a while).
 *
 * Designed to be used with `tail -n0 -F` or as a syslogd program destination.
 * Mails will be sent to the local user invoking the program by default.
 *
 * Original author: Mathieu <sigsys@gmail.com>.
 * No copyrights reserved.
 *
 *
 * NOTES:
 *
 * Monitoring mail server logs (even if indirectly) may cause a mail loop of
 * sorts.  Rate limiting should render this fairly harmless but it might still
 * be annoying or fill up a mail submission queue over time.
 *
 * The mails may end up being larger than the buffer due to line ending
 * conversion, long line splitting, or any other transformation that may occur
 * in transit.
 */

#ifdef BSD
#define PROG_NAME getprogname()
#else
#define PROG_NAME "logmail"
#endif

struct run {
	char *buffer_base;
	size_t buffer_fill, buffer_size;
	time_t min_delay, acc_delay, max_delay;
	time_t cur_delay, inc_delay;
	time_t waited;
	off_t io_discarded;
	time_t io_begin_time, io_saved_time, io_end_time;
	int input_fd;
	bool input_eof;
	bool fork_on_eof;
	bool wait_on_eof;
	bool generate_mail;
	char *mail_subject;
	char *mail_tag;
	char **mail_fields;
	char **mail_recipients;
	char **program;
	bool debug;
};


static char *
rfc2822_date(time_t time) {
	static char b[256];
	struct tm *l;
	size_t n;
	l = localtime(&time);
	n = strftime(b, sizeof b, "%a, %d %b %Y %T %z (%Z)", l);
	if (!n)
		*b = '\0';
	return b;
}

static int
write_header(struct run *run, int fd) {
	time_t now;
	FILE *hdr;
	char **pp;
	fd = dup(fd);
	if (fd < 0)
		return warn("dup"), -1;
	hdr = fdopen(fd, "w");
	if (!hdr) {
		close(fd);
		return warn("fdopen"), -1;
	}
	time(&now);

	/* XXX: No sanitization is being done. */

	fprintf(hdr, "Auto-Submitted: auto-generated\n");
	if (run->mail_recipients)
		for (pp = run->mail_recipients; *pp; pp++)
			fprintf(hdr, "To: %s\n", *pp);
	fprintf(hdr, "X-LogMail-Begin: %s\n", rfc2822_date(run->io_begin_time));
	fprintf(hdr, "X-LogMail-Saved: %s\n", rfc2822_date(run->io_saved_time));
	fprintf(hdr, "X-LogMail-End: %s\n", rfc2822_date(run->io_end_time));
	fprintf(hdr, "X-LogMail-Submitted: %s\n", rfc2822_date(now));
	fprintf(hdr, "X-LogMail-Next: %s\n", rfc2822_date(now + run->cur_delay));
	fprintf(hdr, "X-LogMail-Discarded: %ju\n", (uintmax_t)run->io_discarded);
	fprintf(hdr, "X-LogMail-EOF: %s\n", run->input_eof ? "yes" : "no");
	if (run->mail_tag)
		fprintf(hdr, "X-LogMail-Tag: %s\n", run->mail_tag);
	if (run->mail_subject)
		fprintf(hdr, "Subject: %s\n", run->mail_subject);
	if (run->mail_fields)
		for (pp = run->mail_fields; *pp; pp++)
			fprintf(hdr, "%s\n", *pp);
	fprintf(hdr, "\n");

	fclose(hdr);
	if (ferror(hdr))
		return warn("stdio"), -1;
	return 0;
}

static int
write_message(struct run *run, int fd) {
	int r;
	if (run->generate_mail) {
		r = write_header(run, fd);
		if (r < 0)
			return r;
	}
	char *buf = run->buffer_base;
	size_t len = run->buffer_fill;
	while (len) {
		r = write(fd, buf, len);
		if (r <= 0)
			return warn("write"), -1;
		buf += r;
		len -= r;
	}
	return 0;
}


static int
dispatch(struct run *run) {
	int r, pipe_fds[2], status;
	pid_t child_pid;
	bool failed = false;

	r = pipe(pipe_fds);
	if (r < 0)
		return warn("pipe"), -1;

	fflush(stderr);

	child_pid = fork();

	if (0 == child_pid) { /* in child process */
#ifdef BSD
		err_set_exit(_exit);
#endif
		r = close(pipe_fds[1]);
		if (r < 0)
			warn("close");
		r = dup2(pipe_fds[0], STDIN_FILENO);
		if (r < 0)
			err(EX_OSERR, "dup2");
		r = close(pipe_fds[0]);
		if (r < 0)
			warn("close");
		execvp(run->program[0], run->program);
		err(EX_UNAVAILABLE, "%s", run->program[0]);
	}

	if (child_pid < 0) {
		warn("fork");
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		return -1;
	}

	r = close(pipe_fds[0]);
	if (r < 0)
		warn("close");

	r = write_message(run, pipe_fds[1]);
	if (r < 0)
		failed = true;

	r = close(pipe_fds[1]);
	if (r < 0) {
		failed = true;
		warn("close");
	}

	r = waitpid(child_pid, &status, 0);
	if (r < 0) {
		failed = true;
		warn("waitpid %d", child_pid);
	} else {
		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status) != 0) {
				failed = true;
				warnx("%s: exited with status %d", run->program[0],
				      WEXITSTATUS(status));
			}
		} else {
			failed = true;
			warnx("%s: exited on signal %d (%s)", run->program[0],
			      WTERMSIG(status), strsignal(WTERMSIG(status)));
		}
	}

	if (failed) /* keep buffer for next try */
		return -1;

	/* This could be sensitive information, don't keep in memory
	 * potentially forever. */
	memset(run->buffer_base, '\0', run->buffer_fill);

	run->buffer_fill = 0;

	run->io_discarded = 0;
	run->io_begin_time = run->io_saved_time = run->io_end_time = 0;

	return 0;
}


static void
drain_input(struct run *run) { /* fill buffer or discard input if full */
	char discard[1 << 12];
	size_t space = run->buffer_size - run->buffer_fill;
	char *buffer = run->buffer_base + run->buffer_fill;
	int r;
	r = read(run->input_fd, space ? buffer : discard,
	                        space ? space : sizeof discard);
	if (r == 0) {
		run->input_eof = true;
	} else if (r < 0) {
		run->input_eof = errno != EWOULDBLOCK && errno != EAGAIN;
		warn("read");
	} else {
		time(&run->io_end_time);
		if (!run->buffer_fill)
			run->io_begin_time = run->io_end_time;
		if (space) {
			run->io_saved_time = run->io_end_time;
			run->buffer_fill += r;
		} else
			run->io_discarded += r;
	}
}

static void
process(struct run *run, bool input_ready, time_t elapsed) {
	bool buffer_filled;

	if (run->cur_delay > elapsed) {
		run->cur_delay -= elapsed;
		elapsed = 0;
	} else {
		elapsed -= run->cur_delay;
		run->cur_delay = 0;
	}

	buffer_filled = run->buffer_fill;
	if (input_ready) {
		drain_input(run);
		if (!buffer_filled && run->buffer_fill) {
			/* Buffer was not filled but became filled.  Allow some
			 * extra time for accumulation. */
			if (run->cur_delay < run->acc_delay)
				run->cur_delay = run->acc_delay;
			buffer_filled = true;
		}
	}

	if ((run->waited += elapsed)) { /* waited some extra time */
		/* Halve the required delay for the next mail for every unit of
		 * maximum delay of extra time we've waited since the last mail. */
		run->inc_delay >>= run->waited / run->max_delay;
		if (run->inc_delay < run->min_delay)
			run->inc_delay = run->min_delay;
		run->waited %= run->max_delay;
	}

	if (!run->cur_delay && buffer_filled) { /* ready to send buffer */
		run->cur_delay = run->inc_delay;
		run->waited = 0;

		/* Double the required delay for the next mail every time we
		 * send a mail. */
		time_t t = run->inc_delay << 1;
		if (t < run->inc_delay || t > run->max_delay)
			run->inc_delay = run->max_delay;
		else
			run->inc_delay = t;

		dispatch(run);
	}
}

static void
main_loop(struct run *run) {
	int r;

	/* Most OSes probably don't need this anymore, but set non-blocking
	 * mode on input just to be safe. */
	r = fcntl(run->input_fd, F_GETFL);
	if (r < 0) {
		warn("fcntl");
	} else {
		r = fcntl(run->input_fd, F_SETFL, r | O_NONBLOCK);
		if (r < 0)
			warn("fcntl");
	}

	struct pollfd pfd = { .fd = run->input_fd, .events = POLLIN|POLLHUP };
	time_t time0;
	time(&time0);
	while (!run->input_eof || run->buffer_fill) {
		if (run->debug)
			warnx("delay cur/inc: %ld/%ld, waited: %ld, fill: %zu, eof: %d",
			    run->cur_delay, run->inc_delay, run->waited,
			    run->buffer_fill, run->input_eof);
		if (run->input_eof) {
			/* If used as a log destination program with syslogd,
			 * we should exit quickly after getting an EOF on the
			 * input.  syslogd will attempt to restart the program
			 * when reloading its configuration and the mail delay
			 * can be become (much) higher than what it is willing
			 * to wait on. */
			if (!run->wait_on_eof) {
				/* try to mail current buffer immediately */
				run->cur_delay = 0;
				run->inc_delay = run->min_delay;
				/* Don't keep resetting the timers, multiple
				 * mailing attempts may still be done if there
				 * are failures. */
				run->wait_on_eof = true;
			}
			if (run->fork_on_eof) {
				/* handle current buffer in the background */
				pid_t pid;
				if (run->debug)
					warnx("backgrounding");
				pid = fork();
				if (pid < 0)
					warnx("cannot fork, staying in foreground");
				else if (pid > 0)
					_exit(EX_OK);
				/* stop child process from trying to fork again */
				run->fork_on_eof = false;
			}
		}
		int timeout;
		if (run->buffer_fill) {
			timeout = run->cur_delay * 1000;
			if (timeout < run->cur_delay)
				timeout = INT_MAX;
		} else /* avoid unnecessart wakeups if there's nothing to send */
			timeout = -1; /* INFTIM */
		r = poll(&pfd, run->input_eof ? 0 : 1, timeout);
		if (r < 0 && EINTR != errno)
			err(EX_OSERR, "poll");
		time_t time1, elapsed;
		time(&time1);
		/* time since last time the time changed */
		elapsed = time1 > time0 ? time1 - time0 : 0;
		time0 = time1;
		if (run->debug)
			warnx("ready: %d, elapsed: %ld", r > 1, elapsed);
		process(run, r > 0, elapsed);
	}
}


static void
usage(void) {
	fprintf(stderr,
	        "usage: %s [-b buffer_size] [-d min_delay] [-D max_delay] "
	                  "[-s subject] [-t tag] [-r recipient] "
	                  "[-wfmp] " "[arg ...]\n",
                PROG_NAME);
	exit(EX_USAGE);
}

static char *default_program[] = { "sendmail", "-i", "-t", NULL };

int
main(int argc, char **argv) {
	struct run run = {
		.buffer_size = 1 << 16,
		.input_fd = STDIN_FILENO,
		.min_delay = 30,
		.max_delay = 60*60,
		.program = default_program,
	};

	bool custom_program = false;
	char *recipients[argc];
	size_t recipients_count = 0;
	char *fields[argc];
	size_t fields_count = 0;
	char subject_buffer[256];

	int ch;
	while ((ch = getopt(argc, argv, "xwfb:d:D:ms:t:h:r:p?")) != -1)
		switch (ch) {
		case 'x':
			run.debug = true;
			break;
		case 'w':
			run.wait_on_eof = true;
			break;
		case 'f':
			run.fork_on_eof = true;
			break;
		case 'b':
			run.buffer_size = strtoul(optarg, NULL, 10);
			if (!run.buffer_size)
				errx(EX_DATAERR, "invalid buffer size");
			break;
		case 'd':
			run.min_delay = strtoul(optarg, NULL, 10);
			if (!run.min_delay)
				errx(EX_DATAERR, "invalid delay");
			break;
		case 'D':
			run.max_delay = strtoul(optarg, NULL, 10);
			if (!run.max_delay)
				errx(EX_DATAERR, "invalid delay");
			break;
		case 'm':
			run.generate_mail = true;
			break;
		case 's':
			run.mail_subject = optarg;
			break;
		case 't':
			run.mail_tag = optarg;
			break;
		case 'h':
			fields[fields_count++] = optarg;
			break;
		case 'r':
			recipients[recipients_count++] = optarg;
			break;
		case 'p':
			custom_program = true;
			break;
		case '?':
			usage();
			break;
		}
	argc -= optind, argv += optind;

	if (custom_program) {
		if (!argc)
			usage();
		run.program = argv;
	} else {
		run.generate_mail = true;
		while (argc) {
			recipients[recipients_count++] = *argv;
			argc--, argv++;
		}
	}

	if (run.generate_mail) {

		if (!recipients_count) {
			char *rcpt;
			rcpt = getenv("LOGNAME");
			if (!rcpt)
				rcpt = getenv("USER");
			if (!rcpt) {
				uid_t uid = getuid();
				struct passwd *pw;
				errno = 0;
				pw = getpwuid(uid);
				if (pw)
					rcpt = pw->pw_name;
				else if (errno)
					err(EX_OSERR, "getpwuid: %d", uid);
				else
					errx(EX_NOUSER, "getpwuid: %d: %s", uid, "not found");

			}
			recipients[recipients_count++] = rcpt;
		}
		recipients[recipients_count] = NULL;
		run.mail_recipients = recipients;

		fields[fields_count] = NULL;
		run.mail_fields = fields;

		if (!run.mail_subject) {
			char *tag = run.mail_tag;
			char hostname[MAXHOSTNAMELEN + 1];
			int r;
			r = gethostname(hostname, sizeof hostname);
			if (r < 0) {
				warn("gethostname");
				strcpy(hostname, "[unknown]");
			}
			r = snprintf(subject_buffer, sizeof subject_buffer,
			    "%s: %s%slog messages for host %s",
			    PROG_NAME, tag ? tag : "", tag ? " " : "", hostname);
			if (r < 0)
				err(EX_TEMPFAIL, "snprintf");
			run.mail_subject = subject_buffer;
		}

	}

	run.buffer_base = malloc(run.buffer_size);
	if (!run.buffer_base)
		err(EX_TEMPFAIL, "malloc");

	if (run.max_delay < run.min_delay)
		run.max_delay = run.min_delay;
	run.acc_delay = run.min_delay;
	run.inc_delay = run.min_delay;
	run.cur_delay = 0;

	main_loop(&run);

	free(run.buffer_base);

	return EX_OK;
}
