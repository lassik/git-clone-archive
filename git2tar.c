// Copyright 2020 Lassi Kortela
// SPDX-License-Identifier: ISC

#include <sys/stat.h>
#include <sys/wait.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef PROGGIT
#define PROGGIT ""
#endif

#ifndef PROGNAME
#define PROGNAME "git2tar"
#endif

#define PROGRELEASE "0.1.0"

#define TAR_UID 0
#define TAR_GID 0

struct ent {
    unsigned long unix_file_mode;
    char *git_object_type;
    char *git_object_hash;
    char *file_name;
};

static char clonedir[] = PROGNAME "-XXXXXXXX";
static const char *prefix = PROGNAME "/";
static unsigned int vflags;
static int null_device;
static int cleanupdir;
static int should_cleanup;

static void cleanup(void);

static void exit_with_cleanup(int code)
{
    cleanup();
    exit(code);
}

static void fatal(const char *msg)
{
    fprintf(stderr, "%s: %s\n", PROGNAME, msg);
    exit_with_cleanup(2);
}

static void fatal_errno(const char *msg)
{
    fprintf(stderr, "%s: %s: %s\n", PROGNAME, msg, strerror(errno));
    exit_with_cleanup(2);
}

static void announce_argv(const char **argv)
{
    const char *arg;

    if ((vflags >= 3) && argv[0]) {
        fprintf(stderr, "> %s", argv[0]);
        for (argv++; (arg = *argv); argv++) {
            fprintf(stderr, " %s", arg);
        }
        fprintf(stderr, "\n");
    }
}

static void finish(pid_t child)
{
    int status;

    if (waitpid(child, &status, 0) == (pid_t)-1) {
        fatal_errno("cannot wait for git to finish");
    }
    if (!WIFEXITED(status)) {
        fatal("git crashed");
    }
    if (WEXITSTATUS(status) != 0) {
        fatal("git failed");
    }
}

static void run(const char **argv)
{
    pid_t child;

    announce_argv(argv);
    if ((child = fork()) == (pid_t)-1) {
        fatal_errno("cannot fork");
    }
    if (!child) {
        dup2(null_device, STDOUT_FILENO);
        close(null_device);
        execvp(argv[0], (char **)argv);
        _exit(126);
    }
    finish(child);
}

static void outrun(const char **argv, char **out_buf, size_t *out_len)
{
    pid_t child;
    int outpipe[2];
    char *buf;
    size_t buf_cap, buf_len;
    ssize_t nread;

    announce_argv(argv);
    if (pipe(outpipe) == -1) {
        fatal_errno("cannot create pipe");
    }
    if ((child = fork()) == (pid_t)-1) {
        fatal_errno("cannot fork");
    }
    if (!child) {
        dup2(outpipe[1], STDOUT_FILENO);
        close(outpipe[0]);
        close(outpipe[1]);
        close(null_device);
        execvp(argv[0], (char **)argv);
        _exit(126);
    }
    close(outpipe[1]);
    buf = 0;
    buf_len = 0;
    buf_cap = 64;
    for (;;) {
        if (buf_cap - 1 - buf_len < 1) {
            buf_cap *= 2;
        }
        if (!(buf = realloc(buf, buf_cap))) {
            fatal("out of memory");
        }
        for (;;) {
            nread = read(outpipe[0], buf + buf_len, buf_cap - 1 - buf_len);
            if (nread == (ssize_t)-1) {
                if (errno == EINTR) {
                    continue;
                }
                fatal_errno("cannot read from subprocess");
            }
            break;
        }
        if (!nread) {
            break;
        }
        buf_len += (size_t)nread;
    }
    close(outpipe[0]);
    finish(child);
    *out_buf = buf;
    *out_len = buf_len;
}

static char *outrun0(const char **argv)
{
    char *buf;
    size_t len;

    outrun(argv, &buf, &len);
    if (memchr(buf, 0, len)) {
        fatal("null byte in git output");
    }
    buf[len] = 0;
    return buf;
}

static void remove_final_newline(char *string)
{
    char *limit;

    if ((limit = strchr(string, 0)) > string) {
        if (limit[-1] == '\n') {
            limit--;
        }
    }
    *limit = 0;
}

static void remove_final_slashes(char *string)
{
    char *limit;

    for (limit = strchr(string, 0); limit > string; limit--) {
        if (limit[-1] != '/') {
            break;
        }
    }
    *limit = 0;
}

static void git_clone(const char *url, const char *clonedir)
{
    const char *git_argv[] = { "git", "clone", "--bare", "--depth", "1", "--",
        url, clonedir, 0 };

    run(git_argv);
}

static void git_clone_branch(
    const char *url, const char *clonedir, const char *branch)
{
    const char *git_argv[] = { "git", "clone", "--bare", "--depth", "1",
        "--branch", branch, "--", url, clonedir, 0 };

    run(git_argv);
}

static void git_show(
    const char *git_ref, char **out_contents, size_t *out_filesize)
{
    const char *git_argv[] = { "git", "show", git_ref, 0 };

    outrun(git_argv, out_contents, out_filesize);
}

static char *git_rev_parse(const char *git_ref)
{
    const char *git_argv[] = { "git", "rev-parse", git_ref, 0 };
    char *out;

    out = outrun0(git_argv);
    remove_final_newline(out);
    return out;
}

static char *git_ls_tree(const char *git_ref)
{
    const char *git_argv[] = { "git", "ls-tree", git_ref, 0 };

    return outrun0(git_argv);
}

static char *scan_until(char *str, char **out_span, int sentinel)
{
    char *limit;
    char *span;
    size_t len;

    if (!(limit = strchr(str, sentinel))) {
        fatal("cannot parse");
    }
    len = (size_t)(limit - str);
    if (!(span = calloc(1, len + 1))) {
        fatal("out of memory");
    }
    memcpy(span, str, len);
    span[len] = 0;
    *out_span = span;
    return limit + 1;
}

static unsigned long parse_unix_file_mode(const char *string)
{
    unsigned long bits;

    sscanf(string, "%lo", &bits);
    return bits;
}

static char *parse_ls_tree_entry(char *tree, struct ent **out_ent)
{
    struct ent *ent;
    char *unix_file_mode;

    *out_ent = 0;
    if (!*tree) {
        return 0;
    }
    if (!(ent = calloc(1, sizeof(*ent)))) {
        fatal("out of memory");
    }
    tree = scan_until(tree, &unix_file_mode, ' ');
    ent->unix_file_mode = parse_unix_file_mode(unix_file_mode);
    free(unix_file_mode);
    tree = scan_until(tree, &ent->git_object_type, ' ');
    tree = scan_until(tree, &ent->git_object_hash, '\t');
    tree = scan_until(tree, &ent->file_name, '\n');
    *out_ent = ent;
    return tree;
}

static void free_ls_tree_entry(struct ent *ent)
{
    free(ent->git_object_type);
    free(ent->git_object_hash);
    free(ent->file_name);
    free(ent);
}

static void write_to_stdout(void *buf, size_t len)
{
    if (write(STDOUT_FILENO, buf, len) != (ssize_t)len) {
        fatal("cannot write to stdout");
    }
}

static char path[4096];

static void path_truncate(char *limit)
{
    memset(limit, 0, sizeof(path) - (size_t)(limit - path));
}

static char *path_append(const char *name)
{
    char *pivot;
    char *add;
    size_t room;

    pivot = add = strchr(path, 0);
    if (add > path) {
        *add++ = '/';
    }
    room = sizeof(path) - (size_t)(add - path);
    if ((size_t)snprintf(add, room, "%s", name) >= room) {
        fatal("pathname too long");
    }
    return pivot;
}

static unsigned long sum_bytes(unsigned char *bytes, size_t nbyte)
{
    unsigned long sum = 0;

    for (; nbyte; nbyte--) {
        sum += *bytes++;
    }
    return sum;
}

static char null_bytes[512];
static char tar_header[512];
static char *tar;

static void tar_string(size_t width, const char *value)
{
    size_t len;

    len = strlen(value);
    if (len >= width) {
        fatal("tar limit exceeded");
    }
    memcpy(tar, value, len);
    memset(tar + len, 0, width - len);
    tar += width;
}

static void tar_octal(size_t width, unsigned long value)
{
    size_t ndigit, nzero;
    char digits[width];

    ndigit = (size_t)snprintf(digits, sizeof(digits), "%lo", value);
    if (ndigit >= width) {
        fatal("tar limit exceeded");
    }
    for (nzero = width - 1 - ndigit; nzero; nzero--) {
        *tar++ = '0';
    }
    memcpy(tar, digits, ndigit);
    tar += ndigit;
    *tar++ = 0;
}

static void generate_tar_blob(struct ent *ent)
{
    char *blob;
    char *checksum;
    char *pivot;
    size_t blobsize, i;

    git_show(ent->git_object_hash, &blob, &blobsize);
    memset(tar_header, 0, 512);
    tar = tar_header;
    pivot = path_append(ent->file_name);
    if (vflags >= 2) {
        fprintf(stderr, "%s -> %s (%zu bytes)\n", ent->git_object_hash, path,
            blobsize);
    }
    tar_string(100, path);
    path_truncate(pivot);
    tar_octal(8, ent->unix_file_mode);
    tar_octal(8, TAR_UID);
    tar_octal(8, TAR_GID);
    tar_octal(12, blobsize);
    tar_octal(12, 0); // mtime
    checksum = tar;
    for (i = 0; i < 8; i++) {
        *tar++ = ' ';
    }
    *tar++ = '0';
    tar_string(100, "");
    tar_string(8, "ustar  ");
    tar_string(32, "root");
    tar_string(32, "root");
    tar_string(183, "");
    tar = checksum;
    tar_octal(7, sum_bytes((unsigned char *)tar_header, 512) % 01000000UL);
    write_to_stdout(tar_header, 512);
    write_to_stdout(blob, blobsize);
    write_to_stdout(null_bytes, 512 - (blobsize % 512));
    free(blob);
}

static void generate_tar_tree(const char *hash)
{
    struct ent *ent;
    char *tree;
    char *pivot;

    if (vflags >= 2) {
        fprintf(stderr, "%s -> %s (directory)\n", hash, path);
    }
    tree = git_ls_tree(hash);
    while ((tree = parse_ls_tree_entry(tree, &ent))) {
        if (!strcmp(ent->git_object_type, "blob")) {
            generate_tar_blob(ent);
        } else if (!strcmp(ent->git_object_type, "tree")) {
            pivot = path_append(ent->file_name);
            generate_tar_tree(ent->git_object_hash);
            path_truncate(pivot);
        } else {
            fprintf(stderr, "warning: skipping %s\n", ent->git_object_type);
        }
        free_ls_tree_entry(ent);
    }
    free(tree);
}

static void generate_tar_file(void)
{
    char *hash;

    path_truncate(path);
    path_append(prefix);
    remove_final_slashes(path);
    hash = git_rev_parse("HEAD");
    generate_tar_tree(hash);
    free(hash);
    path_truncate(path);
    write_to_stdout(null_bytes, 512);
    write_to_stdout(null_bytes, 512);
}

static char *get_tmpdir(void)
{
    const char *const_string;
    char *string;

    if (!(const_string = getenv("TMPDIR"))) {
        const_string = "/tmp";
    }
    if (!(string = strdup(const_string))) {
        fatal("out of memory");
    }
    remove_final_slashes(string);
    return string;
}

static void delete_temp_dir(void);

static void delete_temp_ent(void)
{
    static struct stat st;

    if (lstat(path, &st) == -1) {
        fatal_errno("cannot get info for temp file");
    }
    if (S_ISDIR(st.st_mode)) {
        delete_temp_dir();
        if (vflags >= 3) {
            fprintf(stderr, "rmdir  %s\n", path);
        }
        if (rmdir(path) == -1) {
            fatal_errno("cannot delete temp directory");
        }
    } else {
        if (vflags >= 3) {
            fprintf(stderr, "unlink %s\n", path);
        }
        if (unlink(path) == -1) {
            fatal_errno("cannot delete temp file");
        }
    }
}

static void delete_temp_dir(void)
{
    DIR *dir;
    struct dirent *d;
    char *name;
    char *pivot;

    if (!(dir = opendir(path))) {
        fatal_errno("cannot open directory");
    }
    for (;;) {
        errno = 0;
        if (!(d = readdir(dir))) {
            break;
        }
        name = d->d_name;
        if (!strcmp(name, ".") || !strcmp(name, "..")) {
            continue;
        }
        pivot = path_append(name);
        delete_temp_ent();
        path_truncate(pivot);
    }
    if (errno) {
        fatal_errno("cannot list directory");
    }
    if (closedir(dir) == -1) {
        fatal_errno("cannot close directory");
    }
}

static void cleanup(void)
{
    if (!should_cleanup) {
        return;
    }
    should_cleanup = 0;
    if (vflags >= 1) {
        fprintf(stderr, "%s: cleaning up temp files\n", PROGNAME);
    }
    if (fchdir(cleanupdir) == -1) {
        fatal_errno("cannot change directory");
    }
    path_truncate(path);
    path_append(clonedir);
    delete_temp_ent();
    path_truncate(path);
}

static void generic_usage(FILE *stream, int code)
{
    fprintf(stream,
        "usage: %s [--prefix <prefix>] <url> [<branch>]\n"
        "\n"
        "--prefix <prefix>   Add directory to filenames in archive.\n"
        "-v, --verbose       Write status messages to stderr.\n"
        "-V, --version       Write version and exit.\n"
        "-h, --help          Write this usage and exit.\n",
        PROGNAME);
    exit_with_cleanup(code);
}

static void usage(void) { generic_usage(stderr, 2); }

static void version(void)
{
    printf("%s %s", PROGNAME, PROGRELEASE);
    if (PROGGIT[0]) {
        printf(" (git describe: %s)", PROGGIT);
    }
    printf("\n");
    exit_with_cleanup(0);
}

static char **parse_short_option(int option, char **argv)
{
    if (option == 'h') {
        generic_usage(stdout, 0);
    } else if (option == 'V') {
        version();
    } else if (option == 'v') {
        vflags++;
    } else {
        usage();
    }
    return argv;
}

static char **parse_long_option(const char *option, char **argv)
{
    if (!strcmp(option, "help")) {
        generic_usage(stdout, 0);
    } else if (!strcmp(option, "version")) {
        version();
    } else if (!strcmp(option, "verbose")) {
        vflags++;
    } else if (!strcmp(option, "prefix")) {
        if (!*argv) {
            usage();
        }
        prefix = *argv++;
    } else {
        usage();
    }
    return argv;
}

static char **parse_options(char **argv)
{
    const char *arg;
    int short_option;

    while ((arg = *argv)) {
        if (arg[0] != '-') {
            break;
        }
        argv++;
        if (arg[1] == '-') {
            if (arg[2] == '-') {
                usage();
            }
            if (!arg[2]) {
                break;
            }
            argv = parse_long_option(&arg[2], argv);
        } else {
            for (arg++; (short_option = *arg); arg++) {
                argv = parse_short_option(short_option, argv);
            }
        }
    }
    return argv;
}

static void make_pledge(void)
{
#ifdef __OpenBSD__
    if (pledge("stdio rpath cpath tmppath proc exec", 0) == -1) {
        fatal_errno("cannot pledge");
    }
#endif
}

int main(int argc, char **argv)
{
    char *tmpdir;
    const char *url;
    const char *branch;

    make_pledge();
    (void)argc;
    argv++;
    argv = parse_options(argv);
    if (*argv) {
        url = *argv++;
    } else {
        usage();
    }
    if (*argv) {
        branch = *argv++;
    } else {
        branch = 0;
    }
    if (*argv) {
        usage();
    }
    if (prefix[0]) {
        if (prefix[0] == '/') {
            // Leading slashes are not customary in tar archives, and
            // tar(1) displays a warning that it ignores them.
            fatal("prefix cannot start with a slash");
        }
        if (strchr(prefix, 0)[-1] != '/') {
            // Requiring a trailing slash may seem bogus. But it's for
            // consistency with git-archive(1). git-archive(1) acts as
            // expected if you give it a trailing slash, but gives odd
            // results if you don't give one. With that precedent, the
            // least confusing alternative is that we require a slash.
            fatal("prefix must end with a slash");
        }
    }
    if (isatty(STDOUT_FILENO)) {
        fatal("standard output is a terminal");
    }
    umask(0077);
    if ((null_device = open("/dev/null", O_RDWR)) == -1) {
        fatal("cannot open /dev/null");
    }
    tmpdir = get_tmpdir();
    if (chdir(tmpdir) == -1) {
        fatal_errno("cannot change directory");
    }
    if ((cleanupdir = open(".", O_RDONLY | O_DIRECTORY)) == -1) {
        fatal_errno("cannot open directory");
    }
    if (!mkdtemp(clonedir)) {
        fatal_errno("cannot create temporary directory");
    }
    should_cleanup = 1;
    if (vflags >= 1) {
        fprintf(stderr, "%s: %s/%s\n", PROGNAME, tmpdir, clonedir);
    }
    if (branch) {
        git_clone_branch(url, clonedir, branch);
    } else {
        git_clone(url, clonedir);
    }
    if (chdir(clonedir) == -1) {
        fatal_errno("cannot change directory");
    }
    generate_tar_file();
    exit_with_cleanup(0);
    return 0;
}
