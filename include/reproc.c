#include <assert.h>
#include "reproc.h"
#include <stdbool.h>

struct stdio_desp
{
#if defined(_WIN32)
    HANDLE in, out, err;
#else
    int    in, out, err;
#endif
};

struct process_options
{
    // Set the working directory of the child process to `working_directory` if it is not `NULL`.
#if defined(_WIN32)
    const wchar_t * working_directory;
#else
    const    char * working_directory;
#endif

    // Redirect stdin, stdout and stderr to `stdin_fd`, `stdout_fd` and  `stderr_fd` respectively if not zero.
    struct stdio_desp io;

#if defined(_WIN32)
#else
    // `process_group` is passed directly to `setpgid`'s second argument (passing
    // 0 will create a new process group with the same value as the new child
    // process' pid).
    pid_t process_group;

    // Don't wait for `action` to complete in the child process before returning
    // from `process_create`. Returning early also results in errors from `action`
    // not being reported.
    bool return_early;
    bool vfork;
#endif
};


#if defined(_WIN32) && defined(HAVE_ATTRIBUTE_LIST)
#include <stdlib.h>

static REPROC_ERROR handle_inherit_list_create(HANDLE *handles, int amount, LPPROC_THREAD_ATTRIBUTE_LIST *result)
{
    assert(handles);
    assert(amount >= 0);
    assert(result);

    // Get the required size for `attribute_list`.
    SIZE_T attribute_list_size = 0;
    if(!InitializeProcThreadAttributeList(NULL, 1, 0, &attribute_list_size) && GetLastError() != ERROR_INSUFFICIENT_BUFFER){
        return REPROC_UNKNOWN_ERROR;
    }

    LPPROC_THREAD_ATTRIBUTE_LIST attribute_list = malloc(attribute_list_size);
    if(!attribute_list){
        return REPROC_NOT_ENOUGH_MEMORY;
    }

    if(!InitializeProcThreadAttributeList(attribute_list, 1, 0, &attribute_list_size)){
        free(attribute_list);
        return REPROC_UNKNOWN_ERROR;
    }

    // Add the handles to be inherited to `attribute_list`.
    if(!UpdateProcThreadAttribute(attribute_list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles, amount * sizeof(HANDLE), NULL, NULL)){
        DeleteProcThreadAttributeList(attribute_list);
        return REPROC_UNKNOWN_ERROR;
    }

    *result = attribute_list;
    return REPROC_SUCCESS;
}
#endif

/* Creates a child process and calls `action` with `context` in the child
process. The process id of the new child process is assigned to `pid`. If
`vfork` is enabled, make sure any code executed within `action` is within the
constraints of `vfork`. */
REPROC_ERROR
process_create(int (*action)(const void *), const void *context,
               struct process_options *options, pid_t *pid);

REPROC_ERROR process_wait(pid_t pid, unsigned int timeout,
                          unsigned int *exit_status);

REPROC_ERROR process_terminate(pid_t pid);

REPROC_ERROR process_kill(pid_t pid);


REPROC_ERROR pipe_init(int *read, int *write);

REPROC_ERROR pipe_read(int pipe, void *buffer, unsigned int size,
                       unsigned int *bytes_read);

REPROC_ERROR pipe_write(int pipe, const void *buffer, unsigned int to_write,
                        unsigned int *bytes_written);

void fd_close(int *fd)
{
  assert(fd);

  // Do nothing and return if `fd` is 0 (null) so callers don't have to check if
  // a pipe has been closed already.
  if (*fd == 0) {
    return;
  }

  // Avoid `close` errors overriding other system errors.
  int last_system_error = errno;
  close(*fd);
  errno = last_system_error;

  // `close` should not be repeated on error so always set `fd` to 0.
  *fd = 0;
}

const char *reproc_strerror(REPROC_ERROR error)
{
  switch (error) {
  case REPROC_SUCCESS:
    return "success";
  case REPROC_WAIT_TIMEOUT:
    return "wait timeout";
  case REPROC_STREAM_CLOSED:
    return "stream closed";
  case REPROC_PARTIAL_WRITE:
    return "partial write";
  case REPROC_NOT_ENOUGH_MEMORY:
    return "memory error";
  case REPROC_PIPE_LIMIT_REACHED:
    return "pipe limit reached";
  case REPROC_INTERRUPTED:
    return "interrupted";
  case REPROC_PROCESS_LIMIT_REACHED:
    return "process limit reached";
  case REPROC_INVALID_UNICODE:
    return "invalid unicode";
  case REPROC_PERMISSION_DENIED:
    return "permission denied";
  case REPROC_SYMLINK_LOOP:
    return "symlink loop";
  case REPROC_FILE_NOT_FOUND:
    return "file not found";
  case REPROC_NAME_TOO_LONG:
    return "name too long";
  case REPROC_ARGS_TOO_LONG:
    return "args too long";
  case REPROC_NOT_EXECUTABLE:
    return "not executable";
  case REPROC_UNKNOWN_ERROR:
    return "unknown error";
  }

  return "unknown error";
}

REPROC_ERROR reproc_stop(reproc_type *process, REPROC_CLEANUP c1,
                         unsigned int t1, REPROC_CLEANUP c2, unsigned int t2,
                         REPROC_CLEANUP c3, unsigned int t3,
                         unsigned int *exit_status)
{
  assert(process);

  REPROC_CLEANUP operations[3] = { c1, c2, c3 };
  unsigned int timeouts[3] = { t1, t2, t3 };

  // We don't set `error` to `REPROC_SUCCESS` so we can check if `reproc_wait`,
  // `reproc_terminate` or `reproc_kill` succeeded (in which case `error` is set
  // to `REPROC_SUCCESS`).
  REPROC_ERROR error = REPROC_WAIT_TIMEOUT;

  for (int i = 0; i < 3; i++) {
    REPROC_CLEANUP operation = operations[i];
    unsigned int timeout = timeouts[i];

    switch (operation) {
    case REPROC_NOOP:
      continue;
    case REPROC_WAIT:
      break;
    case REPROC_TERMINATE:
      error = reproc_terminate(process);
      break;
    case REPROC_KILL:
      error = reproc_kill(process);
      break;
    }

    // Stop if `reproc_terminate` or `reproc_kill` returned an error.
    if (error != REPROC_SUCCESS && error != REPROC_WAIT_TIMEOUT) {
      break;
    }

    error = reproc_wait(process, timeout, exit_status);
    if (error != REPROC_WAIT_TIMEOUT) {
      break;
    }
  }

  return error;
}

#if defined(_WIN32)
static REPROC_ERROR process_create_win(wchar_t *command_line, struct process_options *options, DWORD *pid, HANDLE *handle)
{
    assert(command_line);
    assert(options);
    assert(pid);
    assert(handle);

    // Create each child process in a new process group
    // so we don't send `CTRL-BREAK` signals to more than one child process in `process_terminate`.
    DWORD creation_flags = CREATE_NEW_PROCESS_GROUP;

#if defined(HAVE_ATTRIBUTE_LIST)
    REPROC_ERROR error = REPROC_SUCCESS;

    // To ensure no handles other than those necessary are inherited
    // we use the approach detailed in https://stackoverflow.com/a/2345126
    HANDLE to_inherit[3];

    if(options->stdin_handle){
        to_inherit[0] = options->stdin_handle;
    }

    if(options->stdout_handle){
        to_inherit[1] = options->stdout_handle;
    }

    if(options->stderr_handle){
        to_inherit[2] = options->stderr_handle;
    }

    LPPROC_THREAD_ATTRIBUTE_LIST attribute_list = NULL;
    error = handle_inherit_list_create(to_inherit, i, &attribute_list);

    if(error){
        return error;
    }

    creation_flags |= EXTENDED_STARTUPINFO_PRESENT;

    STARTUPINFOEXW extended_startup_info = {
        .StartupInfo = {
            .cb         = sizeof(extended_startup_info),
            .dwFlags    = STARTF_USESTDHANDLES,
            .hStdInput  = options->stdin_handle,
            .hStdOutput = options->stdout_handle,
            .hStdError  = options->stderr_handle
        },
        .lpAttributeList = attribute_list
    };

    LPSTARTUPINFOW startup_info_address = &extended_startup_info.StartupInfo;
#else
    STARTUPINFOW startup_info = {
        .cb         = sizeof(startup_info),
        .dwFlags    = STARTF_USESTDHANDLES,
        .hStdInput  = child_stdin,
        .hStdOutput = child_stdout,
        .hStdError  = child_stderr
    };

    LPSTARTUPINFOW startup_info_address = &startup_info;
#endif

    // Make sure the console window of the child process isn't visible. See
    // https://github.com/DaanDeMeyer/reproc/issues/6 and
    // https://github.com/DaanDeMeyer/reproc/pull/7 for more information.
    startup_info_address->dwFlags |= STARTF_USESHOWWINDOW;
    startup_info_address->wShowWindow = SW_HIDE;

    PROCESS_INFORMATION info;

    // Child processes inherit the error mode of their parents
    // To avoid child processes creating error dialogs we set our error mode to
    // not create error dialogs temporarily which is inherited by the child process.
    DWORD previous_error_mode = SetErrorMode(SEM_NOGPFAULTERRORBOX);
    BOOL result = CreateProcessW(NULL, command_line, NULL, NULL, TRUE, creation_flags, NULL, options->working_directory, startup_info_address, &info);

    SetErrorMode(previous_error_mode);

#if defined(HAVE_ATTRIBUTE_LIST)
    DeleteProcThreadAttributeList(attribute_list);
#endif

    // We don't need the handle to the primary thread of the child process.
    handle_close(&info.hThread);

    if(!result){
        switch(GetLastError()){
            case ERROR_FILE_NOT_FOUND: return REPROC_FILE_NOT_FOUND;
            default                  : return REPROC_UNKNOWN_ERROR;
        }
    }

    *pid = info.dwProcessId;
    *handle = info.hProcess;

    return REPROC_SUCCESS;
}

#else
static REPROC_ERROR process_create_posix(int (*action)(const void *), const void *context, struct process_options *options, pid_t *pid)
{
    assert(options->stdin_fd >= 0);
    assert(options->stdout_fd >= 0);
    assert(options->stderr_fd >= 0);
    assert(pid);

    // Predeclare variables so we can use `goto`.
    REPROC_ERROR error = REPROC_SUCCESS;
    pid_t child_pid = 0;
    int child_error = 0;
    unsigned int bytes_read = 0;

    // We create an error pipe to receive errors from the child process. See this
    // answer https://stackoverflow.com/a/1586277 for more information.
    int error_pipe_read = 0;
    int error_pipe_write = 0;
    error = pipe_init(&error_pipe_read, &error_pipe_write);
    if (error) {
        goto __cleanup;
    }

    if (options->vfork) {
        /* The code inside this block is based on code written by a Redhat employee.
           The original code along with detailed comments can be found here:
https://bugzilla.redhat.com/attachment.cgi?id=941229. */

        // Copyright (c) 2014 Red Hat Inc.

        // Block all signals before executing `vfork`.

        sigset_t all_blocked;
        sigset_t old_mask;

        if (sigfillset(&all_blocked) == -1) {
            error = REPROC_UNKNOWN_ERROR;
            goto __cleanup;
        }

        if (pthread_sigmask(SIG_BLOCK, &all_blocked, &old_mask) == -1) {
            error = REPROC_UNKNOWN_ERROR;
            goto __cleanup;
        }

        child_pid = vfork(); // NOLINT

        if (child_pid == 0) {
            // `vfork` succeeded and we're in the child process. This block contains
            // all `vfork` specific child process code.

            // Reset all signals that are not ignored to `SIG_DFL`.

            sigset_t empty_mask;

            if (sigemptyset(&empty_mask) == -1) {
                write(error_pipe_write, &errno, sizeof(errno));
                _exit(errno);
            }

            struct sigaction old_sa;
            struct sigaction new_sa = { .sa_handler = SIG_DFL,
                .sa_mask = empty_mask };

            for (int i = 0; i < NSIG; i++) {
                // Continue if the signal does not exist, is ignored or is already set
                // to the default signal handler.
                if (sigaction(i, NULL, &old_sa) == -1 || old_sa.sa_handler == SIG_IGN ||
                        old_sa.sa_handler == SIG_DFL) {
                    continue;
                }

                if (sigaction(i, &new_sa, NULL) == -1 && errno != EINVAL) {
                    write(error_pipe_write, &errno, sizeof(errno));
                    _exit(errno);
                }
            }

            // Restore the old signal mask.

            if (pthread_sigmask(SIG_SETMASK, &old_mask, NULL) != 0) {
                write(error_pipe_write, &errno, sizeof(errno));
                _exit(errno);
            }
        } else {
            // In the parent process we restore the old signal mask regardless of
            // whether `vfork` succeeded or not.
            if (pthread_sigmask(SIG_SETMASK, &old_mask, NULL) != 0) {
                goto __cleanup;
            }
        }
    } else {
        child_pid = fork();
    }

    // The rest of the code is identical regardless of whether `fork` or `vfork`
    // was used.

    if (child_pid == 0) {
        // Child process code. Since we're in the child process we can exit on
        // error. Why `_exit`? See:
        // https://stackoverflow.com/questions/5422831/what-is-the-difference-between-using-exit-exit-in-a-conventional-linux-fo?noredirect=1&lq=1

        /* Normally there might be a race condition if the parent process waits for
           the child process before the child process puts itself in its own process
           group (using `setpgid`) but this is avoided because we always read from the
           error pipe in the parent process after forking. When `read` returns the
           child process will either have returned an error (and waiting won't be
           valid) or will have executed `_exit` or `exec` (and as a result `setpgid`
           as well). */
        if (setpgid(0, options->process_group) == -1) {
            write(error_pipe_write, &errno, sizeof(errno));
            _exit(errno);
        }

        if (options->working_directory && chdir(options->working_directory) == -1) {
            write(error_pipe_write, &errno, sizeof(errno));
            _exit(errno);
        }

        // Redirect stdin, stdout and stderr if required.
        // `_exit` ensures open file descriptors (pipes) are closed.

        if (options->stdin_fd && dup2(options->stdin_fd, STDIN_FILENO) == -1) {
            write(error_pipe_write, &errno, sizeof(errno));
            _exit(errno);
        }
        if (options->stdout_fd && dup2(options->stdout_fd, STDOUT_FILENO) == -1) {
            write(error_pipe_write, &errno, sizeof(errno));
            _exit(errno);
        }
        if (options->stderr_fd && dup2(options->stderr_fd, STDERR_FILENO) == -1) {
            write(error_pipe_write, &errno, sizeof(errno));
            _exit(errno);
        }

        // Close open file descriptors in the child process.
        int max_fd = (int) sysconf(_SC_OPEN_MAX);
        for (int i = 3; i < max_fd; i++) {
            // We might still need the error pipe so we don't close it. The error pipe
            // is created with `FD_CLOEXEC` which results in it being closed
            // automatically when `exec` or `_exit` are called so we don't have to
            // manually close it.
            if (i == error_pipe_write) {
                continue;
            }

            close(i);
        }
        // Ignore `close` errors since we try to close every file descriptor and
        // `close` sets `errno` when an invalid file descriptor is passed.

        // Closing the error pipe write end will unblock the `pipe_read` call in the
        // parent process which allows it to continue executing.
        if (options->return_early) {
            fd_close(&error_pipe_write);
        }

        // Finally, call the makeshift lambda provided by the caller with the
        // accompanying context object.
        int action_error = action(context);

        // If we didn't return early the error pipe write end is still open and we
        // can use it to report an optional error from action.
        if (!options->return_early) {
            write(error_pipe_write, &action_error, sizeof(action_error));
        }

        _exit(action_error);
    }

    if (child_pid == -1) {
        switch (errno) {
            case EAGAIN:
                error = REPROC_PROCESS_LIMIT_REACHED;
                break;
            case ENOMEM:
                error = REPROC_NOT_ENOUGH_MEMORY;
                break;
            default:
                error = REPROC_UNKNOWN_ERROR;
                break;
        }

        goto __cleanup;
    }

    // Close error pipe write end on the parent's side so `pipe_read` will return
    // when it is closed on the child side as well.
    fd_close(&error_pipe_write);

    // `pipe_read` blocks until an error is reported from the child process or the
    // write end of the error pipe in the child process is closed.
    error = pipe_read(error_pipe_read, &child_error, sizeof(child_error),
            &bytes_read);
    fd_close(&error_pipe_read);

    switch (error) {
        case REPROC_SUCCESS:
            break;
            // `REPROC_STREAM_CLOSED` is not an error because it means the pipe was closed
            // without an error being written to it.
        case REPROC_STREAM_CLOSED:
            break;
        default:
            goto __cleanup;
    }

    // If an error was written to the error pipe we check that a full integer was
    // actually read. We don't expect a partial write to happen but if it ever
    // happens this should make it easier to discover.
    if (error == REPROC_SUCCESS && bytes_read != sizeof(child_error)) {
        error = REPROC_UNKNOWN_ERROR;
        goto __cleanup;
    }

    // If `read` does not return 0 an error will have occurred in the child
    // process (or with `read` itself but this is less likely).
    if (child_error != 0) {
        // Allow retrieving child process errors with `reproc_system_error`.
        errno = child_error;

        switch (child_error) {
            case EACCES:
                error = REPROC_PERMISSION_DENIED;
                break;
            case EPERM:
                error = REPROC_PERMISSION_DENIED;
                break;
            case ELOOP:
                error = REPROC_SYMLINK_LOOP;
                break;
            case ENAMETOOLONG:
                error = REPROC_NAME_TOO_LONG;
                break;
            case ENOENT:
                error = REPROC_FILE_NOT_FOUND;
                break;
            case ENOTDIR:
                error = REPROC_FILE_NOT_FOUND;
                break;
            case EINTR:
                error = REPROC_INTERRUPTED;
                break;
            default:
                error = REPROC_UNKNOWN_ERROR;
                break;
        }

        goto __cleanup;
    }

__cleanup:
    fd_close(&error_pipe_read);
    fd_close(&error_pipe_write);

    // `REPROC_STREAM_CLOSED` is not an error here (see above).
    if (error != REPROC_SUCCESS && error != REPROC_STREAM_CLOSED &&
            child_pid > 0) {
        // Make sure the child process doesn't become a zombie process the child
        // process was started (`child_pid` > 0) but an error occurred.
        if (waitpid(child_pid, NULL, 0) == -1) {
            return REPROC_UNKNOWN_ERROR;
        }

        return error;
    }

    *pid = child_pid;
    return REPROC_SUCCESS;
}
#endif

static unsigned int parse_exit_status(int status)
{
  // `WEXITSTATUS` returns a value between [0,256) so casting to `unsigned int`
  // is safe.
  if (WIFEXITED(status)) {
    return (unsigned int) WEXITSTATUS(status);
  }

  assert(WIFSIGNALED(status));

  return (unsigned int) WTERMSIG(status);
}

static REPROC_ERROR wait_no_hang(pid_t pid, unsigned int *exit_status)
{
  int status = 0;
  // Adding `WNOHANG` makes `waitpid` only check if the child process is still
  // running without waiting.
  pid_t wait_result = waitpid(pid, &status, WNOHANG);
  if (wait_result == 0) {
    return REPROC_WAIT_TIMEOUT;
  } else if (wait_result == -1) {
    // Ignore `EINTR`, it shouldn't happen when using `WNOHANG`.
    return REPROC_UNKNOWN_ERROR;
  }

  if (exit_status) {
    *exit_status = parse_exit_status(status);
  }

  return REPROC_SUCCESS;
}

static REPROC_ERROR wait_infinite(pid_t pid, unsigned int *exit_status)
{
  int status = 0;

  if (waitpid(pid, &status, 0) == -1) {
    switch (errno) {
    case EINTR:
      return REPROC_INTERRUPTED;
    default:
      return REPROC_UNKNOWN_ERROR;
    }
  }

  if (exit_status) {
    *exit_status = parse_exit_status(status);
  }

  return REPROC_SUCCESS;
}

// Makeshift C lambda which is passed to `process_create`.
static int timeout_process(const void *context)
{
  unsigned int milliseconds = *((const unsigned int *) context);

  struct timeval tv;
  tv.tv_sec = milliseconds / 1000;           // ms -> s
  tv.tv_usec = (milliseconds % 1000) * 1000; // leftover ms -> us

  // `select` with no file descriptors can be used as a makeshift sleep function
  // that can still be interrupted.
  if (select(0, NULL, NULL, NULL, &tv) == -1) {
    return errno;
  }

  return 0;
}

static REPROC_ERROR timeout_map_error(int error)
{
  switch (error) {
  case EINTR:
    return REPROC_INTERRUPTED;
  case ENOMEM:
    return REPROC_NOT_ENOUGH_MEMORY;
  default:
    return REPROC_UNKNOWN_ERROR;
  }
}

static REPROC_ERROR wait_timeout(pid_t pid, unsigned int timeout,
                                 unsigned int *exit_status)
{
  assert(timeout > 0);

  REPROC_ERROR error = REPROC_SUCCESS;

  // Check if the child process has already exited before starting a
  // possibly expensive timeout process. If `wait_no_hang` doesn't time out we
  // can return early.
  error = wait_no_hang(pid, exit_status);
  if (error != REPROC_WAIT_TIMEOUT) {
    return error;
  }

  struct process_options options = {
    // `waitpid` supports waiting for the first process that exits in a process
    // group. To take advantage of this we put the timeout process in the same
    // process group as the process we're waiting for.
    .process_group = pid,
    // Return early so `process_create` doesn't block until the timeout has
    // expired.
    .return_early = true,
    // Don't `vfork` because when `vfork` is used the parent process is
    // suspended until the child process calls `exec` or `_exit`.
    // `timeout_process` doesn't call either which results in the parent process
    // being suspended until the timeout process exits. This prevents the parent
    // process from waiting until either the child process or the timeout
    // process expires (which is what we need to do) so we don't use `vfork` to
    // avoid this.
    .vfork = false
  };

  pid_t timeout_pid = 0;
  error = process_create(timeout_process, &timeout, &options, &timeout_pid);
  if (error == REPROC_UNKNOWN_ERROR) {
    error = timeout_map_error(errno);
  }

  if (error) {
    return error;
  }

  // Passing `-reproc->pid` to `waitpid` makes it wait for the first process in
  // the `reproc->pid` process group to exit. The `reproc->pid` process group
  // consists out of the child process we're waiting for and the timeout
  // process. As a result, calling `waitpid` on the `reproc->pid` process group
  // translates to waiting for either the child process or the timeout process
  // to exit.
  int status = 0;
  pid_t exit_pid = waitpid(-pid, &status, 0);

  // If the timeout process exits first the timeout will have expired.
  if (exit_pid == timeout_pid) {
    return REPROC_WAIT_TIMEOUT;
  }

  // If the child process exits first we clean up the timeout process.
  error = process_terminate(timeout_pid);
  if (error) {
    return error;
  }

  error = wait_infinite(timeout_pid, NULL);
  if (error) {
    return error;
  }

  // After cleaning up the timeout process we can check if `waitpid` returned an
  // error.
  if (exit_pid == -1) {
    switch (errno) {
    case EINTR:
      return REPROC_INTERRUPTED;
    default:
      return REPROC_UNKNOWN_ERROR;
    }
  }

  if (exit_status) {
    *exit_status = parse_exit_status(status);
  }

  return REPROC_SUCCESS;
}

REPROC_ERROR process_wait(pid_t pid, unsigned int timeout,
                          unsigned int *exit_status)
{
  if (timeout == 0) {
    return wait_no_hang(pid, exit_status);
  }

  if (timeout == REPROC_INFINITE) {
    return wait_infinite(pid, exit_status);
  }

  return wait_timeout(pid, timeout, exit_status);
}

REPROC_ERROR process_terminate(pid_t pid)
{
  if (kill(pid, SIGTERM) == -1) {
    return REPROC_UNKNOWN_ERROR;
  }

  return REPROC_SUCCESS;
}

REPROC_ERROR process_kill(pid_t pid)
{
  if (kill(pid, SIGKILL) == -1) {
    return REPROC_UNKNOWN_ERROR;
  }

  return REPROC_SUCCESS;
}

// Makeshift C lambda which is passed to `process_create`.
static int exec_process(const void *context)
{
  const char *const *argv = context;

  // Replace the forked process with the process specified in `argv`'s first
  // element. The cast is safe since `execvp` doesn't actually change the
  // contents of `argv`.
  if (execvp(argv[0], (char **) argv) == -1) {
    return errno;
  }

  return 0;
}

static REPROC_ERROR exec_map_error(int error)
{
  switch (error) {
  case E2BIG:
    return REPROC_ARGS_TOO_LONG;
  case EACCES:
    return REPROC_PERMISSION_DENIED;
  case ELOOP:
    return REPROC_SYMLINK_LOOP;
  case EMFILE:
    return REPROC_PROCESS_LIMIT_REACHED;
  case ENAMETOOLONG:
    return REPROC_NAME_TOO_LONG;
  case ENOENT:
    return REPROC_FILE_NOT_FOUND;
  case ENOTDIR:
    return REPROC_FILE_NOT_FOUND;
  case ENOEXEC:
    return REPROC_NOT_EXECUTABLE;
  case ENOMEM:
    return REPROC_NOT_ENOUGH_MEMORY;
  case EPERM:
    return REPROC_PERMISSION_DENIED;
  default:
    return REPROC_UNKNOWN_ERROR;
  }
}

REPROC_ERROR reproc_start(reproc_type *process, int argc, const char *const *argv, const char *working_directory)
{
    assert(process);

    assert(argc > 0);
    assert(argv);
    assert(argv[argc] == NULL);

    for (int i = 0; i < argc; i++) {
        assert(argv[i]);
    }

  // Predeclare every variable so we can use `goto`.

  int child_stdin = 0;
  int child_stdout = 0;
  int child_stderr = 0;

  REPROC_ERROR error = REPROC_SUCCESS;

  error = pipe_init(&child_stdin, &process->in);
  if(error){
    goto __cleanup;
  }

  error = pipe_init(&process->out, &child_stdout);
  if (error) {
    goto __cleanup;
  }

  error = pipe_init(&process->err, &child_stderr);
  if (error) {
    goto __cleanup;
  }

  struct process_options options = {
    .working_directory = working_directory,
    .stdin_fd = child_stdin,
    .stdout_fd = child_stdout,
    .stderr_fd = child_stderr,
    // We put the child process in its own process group which is needed by
    // `wait_timeout` in `process.c` (see `wait_timeout` for extra information).
    .process_group = 0,
    // Don't return early to make sure we receive errors reported by `exec`.
    .return_early = false,
    .vfork = true
  };

  // Fork a child process and call `exec`.
  error = process_create(exec_process, argv, &options, &process->id);
  if (error == REPROC_UNKNOWN_ERROR) {
    error = exec_map_error(errno);
  }

__cleanup:
  // Either an error has ocurred or the child pipe endpoints have been copied to
  // the stdin/stdout/stderr streams of the child process. Either way they can
  // be safely closed in the parent process.
  fd_close(&child_stdin);
  fd_close(&child_stdout);
  fd_close(&child_stderr);

  if (error) {
    reproc_destroy(process);
  }

  return error;
}

REPROC_ERROR reproc_read(reproc_type *process, REPROC_STREAM stream,
                         void *buffer, unsigned int size,
                         unsigned int *bytes_read)
{
  assert(process);
  assert(stream != REPROC_IN);
  assert(buffer);
  assert(bytes_read);

  switch (stream) {
  case REPROC_IN:
    break;
  case REPROC_OUT:
    return pipe_read(process->out, buffer, size, bytes_read);
  case REPROC_ERR:
    return pipe_read(process->err, buffer, size, bytes_read);
  }

  assert(0);
  return REPROC_UNKNOWN_ERROR;
}

REPROC_ERROR reproc_write(reproc_type *process, const void *buffer,
                          unsigned int to_write, unsigned int *bytes_written)
{
  assert(process);
  assert(process->in != 0);
  assert(buffer);
  assert(bytes_written);

  return pipe_write(process->in, buffer, to_write, bytes_written);
}

void reproc_close(reproc_type *process, REPROC_STREAM stream)
{
    assert(process);

    switch (stream) {
        case REPROC_IN:
            fd_close(&process->in);
            return;
        case REPROC_OUT:
            fd_close(&process->out);
            return;
        case REPROC_ERR:
            fd_close(&process->err);
            return;
    }

    assert(0);
}

REPROC_ERROR reproc_wait(reproc_type *process, unsigned int timeout,
                         unsigned int *exit_status)
{
  assert(process);

  return process_wait(process->id, timeout, exit_status);
}

REPROC_ERROR reproc_terminate(reproc_type *process)
{
  assert(process);

  return process_terminate(process->id);
}

REPROC_ERROR reproc_kill(reproc_type *process)
{
  assert(process);

  return process_kill(process->id);
}

void reproc_destroy(reproc_type *process)
{
    assert(process);

#if defined(_WIN32)
    handle_close(&process->handle);
    handle_close(&process->in);
    handle_close(&process->out);
    handle_close(&process->err);
#else
    fd_close(&process->in);
    fd_close(&process->out);
    fd_close(&process->err);
#endif
}
const unsigned int REPROC_INFINITE = 0xFFFFFFFF;

REPROC_ERROR pipe_init(int *read, int *write)
{
    assert(read);
    assert(write);

    int pipefd[2];

    // See avoiding resource leaks section in readme for a detailed explanation.
#if defined(HAVE_PIPE2)
    int result = pipe2(pipefd, O_CLOEXEC);
#else
    int result = pipe(pipefd);
    fcntl(pipefd[0], F_SETFD, FD_CLOEXEC);
    fcntl(pipefd[1], F_SETFD, FD_CLOEXEC);
#endif

    if(result == -1){
        switch(errno){
            case ENFILE: return REPROC_PIPE_LIMIT_REACHED;
            default    : return REPROC_UNKNOWN_ERROR;
        }
    }

    // Assign file descriptors if `pipe` call was succesfull.
    *read  = pipefd[0];
    *write = pipefd[1];

    return REPROC_SUCCESS;
}

REPROC_ERROR pipe_read(int pipe, void *buffer, unsigned int size,
                       unsigned int *bytes_read)
{
  assert(buffer);
  assert(bytes_read);

  *bytes_read = 0;

  ssize_t error = read(pipe, buffer, size);
  // `read` returns 0 to indicate the other end of the pipe was closed.
  if (error == 0) {
    return REPROC_STREAM_CLOSED;
  } else if (error == -1) {
    switch (errno) {
    case EINTR:
      return REPROC_INTERRUPTED;
    default:
      return REPROC_UNKNOWN_ERROR;
    }
  }

  // If `error` is not -1 or 0 it represents the amount of bytes read.
  // The cast is safe since `size` is an unsigned int and `read` will not read
  // more `size` bytes.
  *bytes_read = (unsigned int) error;

  return REPROC_SUCCESS;
}

REPROC_ERROR posix_pipe_write(int pipe, const void *buffer, size_t to_write, size_t *bytes_written)
{
    assert(buffer);
    assert(bytes_written);

    *bytes_written = 0;

    ssize_t res = write(pipe, buffer, to_write);
    if(res == -1){
        switch(errno){
            // `write` sets `errno` to `EPIPE` to indicate the other end of the pipe was closed
            case EPIPE: return REPROC_STREAM_CLOSED;
            case EINTR: return REPROC_INTERRUPTED;
            default   : return REPROC_UNKNOWN_ERROR;
        }
    }

    // If `res` is not -1 it represents the amount of bytes written.
    // The cast is safe since it's impossible to write more bytes than `to_write` which is an unsigned int.
    *bytes_written = (unsigned int) res;

    if(*bytes_written != to_write){
        return REPROC_PARTIAL_WRITE;
    }
    return REPROC_SUCCESS;
}

REPROC_ERROR reproc_start(reproc_type *process, int argc, const char *const *argv, const char *working_directory)
{
    assert(process);

    assert(argc > 0);
    assert(argv);
    assert(argv[argc] == NULL);

    for (int i = 0; i < argc; i++) {
        assert(argv[i]);
    }

    // Predeclare every variable so we can use `goto`.

    HANDLE child_stdin = NULL;
    HANDLE child_stdout = NULL;
    HANDLE child_stderr = NULL;

    char *command_line_string = NULL;
    wchar_t *command_line_wstring = NULL;
    wchar_t *working_directory_wstring = NULL;

    REPROC_ERROR error = REPROC_SUCCESS;

    // While we already make sure the child process only inherits the child pipe
    // handles using `STARTUPINFOEXW` (see `process_utils.c`) we still disable
    // inheritance of the parent pipe handles to lower the chance of child
    // processes not created by reproc unintentionally inheriting these handles.
    error = pipe_init(&child_stdin, true, &process->in, false);
    if (error) {
        goto __cleanup;
    }

    error = pipe_init(&process->out, false, &child_stdout, true);
    if (error) {
        goto __cleanup;
    }

    error = pipe_init(&process->err, false, &child_stderr, true);
    if (error) {
        goto __cleanup;
    }

    // Join `argv` to a whitespace delimited string as required by
    // `CreateProcessW`.
    error = string_join(argv, argc, &command_line_string);
    if (error) {
        goto __cleanup;
    }

    // Convert UTF-8 to UTF-16 as required by `CreateProcessW`.
    error = string_to_wstring(command_line_string, &command_line_wstring);
    if (error) {
        goto __cleanup;
    }

    // Do the same for `working_directory` if it isn't `NULL`.
    error = working_directory
        ? string_to_wstring(working_directory, &working_directory_wstring)
        : REPROC_SUCCESS;
    if (error) {
        goto __cleanup;
    }

    struct process_options options = {
        .working_directory = working_directory_wstring,
        .stdin_handle = child_stdin,
        .stdout_handle = child_stdout,
        .stderr_handle = child_stderr
    };

    error = process_create(command_line_wstring, &options, &process->id,
            &process->handle);

__cleanup:
    // Either an error has ocurred or the child pipe endpoints have been copied to
    // the stdin/stdout/stderr streams of the child process. Either way they can
    // be safely closed in the parent process.
    handle_close(&child_stdin);
    handle_close(&child_stdout);
    handle_close(&child_stderr);

    free(command_line_wstring);
    free(working_directory_wstring);

    if (error) {
        reproc_destroy(process);
    }

    return error;
}

REPROC_ERROR reproc_read(reproc_type *process, REPROC_STREAM stream,
                         void *buffer, unsigned int size,
                         unsigned int *bytes_read)
{
  assert(process);
  assert(stream != REPROC_IN);
  assert(buffer);
  assert(bytes_read);

  switch (stream) {
  case REPROC_IN:
    break;
  case REPROC_OUT:
    return pipe_read(process->out, buffer, size, bytes_read);
  case REPROC_ERR:
    return pipe_read(process->err, buffer, size, bytes_read);
  }

  assert(0);
  return REPROC_UNKNOWN_ERROR;
}

REPROC_ERROR reproc_write(reproc_type *process, const void *buffer,
                          unsigned int to_write, unsigned int *bytes_written)
{
  assert(process);
  assert(process->in);
  assert(buffer);
  assert(bytes_written);

  return pipe_write(process->in, buffer, to_write, bytes_written);
}

void reproc_close(reproc_type *process, REPROC_STREAM stream)
{
  assert(process);

  switch (stream) {
  case REPROC_IN:
    handle_close(&process->in);
    return;
  case REPROC_OUT:
    handle_close(&process->out);
    return;
  case REPROC_ERR:
    handle_close(&process->err);
    return;
  }

  assert(0);
}

REPROC_ERROR reproc_wait(reproc_type *process, unsigned int timeout,
                         unsigned int *exit_status)
{
  assert(process);

  return process_wait(process->handle, timeout, exit_status);
}

REPROC_ERROR reproc_terminate(reproc_type *process)
{
  assert(process);

  return process_terminate(process->id);
}

REPROC_ERROR reproc_kill(reproc_type *process)
{
  assert(process);

  return process_kill(process->handle);
}

void reproc_destroy(reproc_type *process)
{
  assert(process);

  handle_close(&process->handle);

  handle_close(&process->in);
  handle_close(&process->out);
  handle_close(&process->err);
}

// Disables a single endpoint of a pipe from being inherited by the child
// process.
static REPROC_ERROR pipe_disable_inherit(HANDLE pipe)
{
  assert(pipe);

  if (!SetHandleInformation(pipe, HANDLE_FLAG_INHERIT, 0)) {
    return REPROC_UNKNOWN_ERROR;
  }

  return REPROC_SUCCESS;
}

REPROC_ERROR pipe_init(HANDLE *read, bool inherit_read, HANDLE *write, bool inherit_write)
{
  assert(read);
  assert(write);

  // Ensures both endpoints of the pipe are inherited by the child process.
  static SECURITY_ATTRIBUTES security_attributes =
  {
      .nLength              = sizeof(SECURITY_ATTRIBUTES),
      .bInheritHandle       = TRUE,
      .lpSecurityDescriptor = NULL
  };

  if (!CreatePipe(read, write, &security_attributes, 0)) {
    return REPROC_UNKNOWN_ERROR;
  }

  REPROC_ERROR error = REPROC_SUCCESS;

  if (!inherit_read) {
    error = pipe_disable_inherit(*read);
    if (error) {
      goto cleanup;
    }
  }

  if (!inherit_write) {
    error = pipe_disable_inherit(*write);
    if (error) {
      goto cleanup;
    }
  }

cleanup:
  if (error) {
    handle_close(read);
    handle_close(write);
  }

  return error;
}

REPROC_ERROR pipe_read(HANDLE pipe, void *buffer, unsigned int size,
                       unsigned int *bytes_read)
{
  assert(pipe);
  assert(buffer);
  assert(bytes_read);

  // The cast is safe since `DWORD` is a typedef to `unsigned int` on Windows.
  if (!ReadFile(pipe, buffer, size, (LPDWORD) bytes_read, NULL)) {
    switch (GetLastError()) {
    case ERROR_OPERATION_ABORTED:
      return REPROC_INTERRUPTED;
    case ERROR_BROKEN_PIPE:
      return REPROC_STREAM_CLOSED;
    default:
      return REPROC_UNKNOWN_ERROR;
    }
  }

  return REPROC_SUCCESS;
}

REPROC_ERROR win_pipe_write(HANDLE pipe, const void *buffer, size_t to_write, size_t *bytes_written)
{
    assert(pipe);
    assert(buffer);
    assert(bytes_written);

    DWORD written = 0;
    if(!WriteFile(pipe, buffer, to_write, (LPDWORD)(&written), NULL)){
        switch(GetLastError()){
            case ERROR_OPERATION_ABORTED: return REPROC_INTERRUPTED;
            case ERROR_BROKEN_PIPE      : return REPROC_STREAM_CLOSED;
            default                     : return REPROC_UNKNOWN_ERROR;
        }
    }

    if(written != (DWORD)(to_write)){
        return REPROC_PARTIAL_WRITE;
    }

    *bytes_written = (size_t)(written);
    return REPROC_SUCCESS;
}
