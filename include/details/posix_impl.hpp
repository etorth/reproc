/*
 * =====================================================================================
 *
 *       Filename: posix_impl.hpp
 *        Created: 01/16/2019 23:23:07
 *    Description: 
 *
 *        Version: 1.0
 *       Revision: none
 *       Compiler: gcc
 *
 *         Author: ANHONG
 *          Email: anhonghe@gmail.com
 *   Organization: USTC
 *
 * =====================================================================================
 */

namespace xmproc::details::posix_impl
{
    struct pipe_closer
    {
        int &fd_ref;
        bool dismiss = false;

        pipe_closer(int &ref)
            : fd_ref(ref)
        {}

        ~pipe_closer()
        {
            if(dismiss){
                return;
            }

            if(fd_ref >= 0){
                int errno_backup = errno;
                close(fd_ref);

                errno  = errno_backup;
                fd_ref = -1;
            }
        }
    };

    struct child_pid_waiter
    {
        pid_t &child_pidref;
        bool dismiss = false;

        child_pid_waiter(pid_t &pid_ref)
            : child_pidref(pid_ref)
        {}

        ~child_pid_waiter()
        {
            if(dismiss){
                return;
            }


        }


    }

    xmproc::errcode process_create(xmproc::details::proc_args *args)
    {
        assert(args->fd_stdin  >= 0);
        assert(args->fd_stdout >= 0);
        assert(args->fd_stderr >= 0);

        // Predeclare variables so we can use `goto`.
        REPROC_ERROR error = REPROC_SUCCESS;

        pid_t child_pid = -1;
        child_pid_waiter pid_waiter(child_pid);

        int child_error = 0;
        unsigned int bytes_read = 0;

        // We create an error pipe to receive errors from the child process, see this anwser:
        // https://stackoverflow.com/a/1586277

        int error_pipe_read  = -1;
        int error_pipe_write = -1;

        auto_fd_closer closer1(error_pipe_read );
        auto_fd_closer closer2(error_pipe_write);

        if(auto ec = xmproc::detailed::posix_impl::pipe_setup(&error_pipe_read, &error_pipe_write)){
            return ec;
        }

        if(!args->use_vfork){

            child_pid = fork();

        }else{
            // check code from:
            // https://github.com/etorth/safe_vfork

            // Block all signals before executing `vfork`.
            sigset_t all_blocked;
            sigset_t old_sigmask;

            if(sigfillset(&all_blocked) == -1){
                return xmproc::error::unknown_error;
            }

            if(pthread_sigmask(SIG_BLOCK, &all_blocked, &old_sigmask) == -1){
                return xmproc::error::unknown_error;
            }

            child_pid = vfork(); // NOLINT

            if(child_pid == 0){
                // `vfork` succeeded and we're in the child process.
                // This block contains all `vfork` specific child process code.

                // Reset all signals that are not ignored to `SIG_DFL`.
                sigset_t empty_sigmask;

                if(sigemptyset(&empty_sigmask) == -1){
                    write(error_pipe_write, &errno, sizeof(errno));
                    _exit(errno);
                }

                struct sigaction old_sa;
                struct sigaction new_sa =
                {
                    .sa_handler = SIG_DFL,
                    .sa_mask    = empty_sigmask
                };

                for(int i = 0; i < NSIG; i++){
                    // skip the signal if it:
                    //    1. non-existing
                    //    2. ignored
                    //    3. already set to the default signal handler
                    if((sigaction(i, NULL, &old_sa) == -1) || (old_sa.sa_handler == SIG_IGN) || (old_sa.sa_handler == SIG_DFL)){
                        continue;
                    }

                    // errno is EINVAL when:
                    //    1. signal is invalid
                    //    2. signal is SIGKILL or SIGSTOP

                    if(sigaction(i, &new_sa, NULL) == -1 && errno != EINVAL){
                        write(error_pipe_write, &errno, sizeof(errno));
                        _exit(errno);
                    }
                }

                // Restore the old signal mask (of its parent process)
                if(pthread_sigmask(SIG_SETMASK, &old_sigmask, NULL) != 0){
                    write(error_pipe_write, &errno, sizeof(errno));
                    _exit(errno);
                }
            }else{
                // In the parent process
                // we restore the old signal mask regardless of whether `vfork` succeeded or not.
                if(pthread_sigmask(SIG_SETMASK, &old_sigmask, NULL) != 0){
                    goto __cleanup;
                }
            }
        }

        if(child_pid == 0){
            // Child process code.

            // Since we're in the child process we can exit on error. Why `_exit`? See:
            // https://stackoverflow.com/questions/5422831/what-is-the-difference-between-using-exit-exit-in-a-conventional-linux-fo

            // Normally there might be a race condition if the parent process waits for the child process before the
            // child process puts itself in its own process group (using `setpgid`) but this is avoided because we
            // always read from the error pipe in the parent process after forking.

            // When `read` returns the child process will either have returned an error (and waiting won't be valid) or
            // will have executed `_exit` or `exec` (and as a result `setpgid` as well).

            if(setpgid(0, args->process_group) == -1){
                write(error_pipe_write, &errno, sizeof(errno));
                _exit(errno);
            }

            if(args->working_directory && chdir(args->working_directory) == -1){
                write(error_pipe_write, &errno, sizeof(errno));
                _exit(errno);
            }

            // Redirect stdin, stdout and stderr if required.
            // `_exit` ensures open file descriptors (pipes) are closed.

            if((args->stdin_fd >= 0) && (dup2(args->stdin_fd, STDIN_FILENO) == -1)){
                write(error_pipe_write, &errno, sizeof(errno));
                _exit(errno);
            }

            if((args->stdout_fd >= 0) && (dup2(args->stdout_fd, STDOUT_FILENO) == -1)){
                write(error_pipe_write, &errno, sizeof(errno));
                _exit(errno);
            }

            if((args->stderr_fd >= 0) && (dup2(args->stderr_fd, STDERR_FILENO) == -1)){
                write(error_pipe_write, &errno, sizeof(errno));
                _exit(errno);
            }

            // If need to redirect stderr to stdout
            // we should put args->stderr_fd as args->stdout_fd in arguments

            // Close all opened file descriptors in the child process.
            // after this step, args->stdin/stdout/stderr in child process is closed
            int max_fd = (int)(sysconf(_SC_OPEN_MAX));

            for(int fd = 0; fd < max_fd; fd++){
                // We might still need the error pipe so we don't close it.
                // The error pipe is created with `FD_CLOEXEC` which results in it being closed
                // automatically when `exec` or `_exit` are called so we don't have to manually close it.
                if(fd == error_pipe_write || fd == STDIN_FILENO || fd == STDOUT_FILENO || fd == STDERR_FILENO){
                    continue;
                }

                if(close(fd) == -1){
                    // here ignore `close` errors since we try to close every file descriptor
                }
            }

            // Closing the error pipe write end will unblock the `pipe_read` call in the
            // parent process which allows it to continue executing.
            if(args->earily_unblock){
                fd_close(&error_pipe_write);
            }

            // Finally, call the makeshift lambda provided by the caller
            int action_errcode = args->action(args->context);

            // If we didn't return early the error pipe write end is still open
            // use it to report an optional error from action
            if(!args->earily_unblock){
                write(error_pipe_write, &action_errcode, sizeof(action_errcode));
            }

            // If we reach here
            // we done everything for child process logic
            _exit(action_errcode);
        }

        if(child_pid == -1){
            switch(errno){
                case EAGAIN:
                    error = xmproc::errcode::process_limit_reached;
                    break;
                case ENOMEM:
                    error = xmproc::errcode::no_memory;
                    break;
                default:
                    error = xmproc::errcode::unknow_error;
                    break;
            }
            goto __cleanup;
        }

        // Close error pipe write end on the parent's side
        // `pipe_read` will return when it is closed on the child side as well.
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
        if (error != REPROC_SUCCESS && error != REPROC_STREAM_CLOSED && child_pid > 0) {
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

        struct process_options args = {
            // `waitpid` supports waiting for the first process that exits in a process
            // group. To take advantage of this we put the timeout process in the same
            // process group as the process we're waiting for.
            .process_group = pid,
            // Return early so `process_create` doesn't block until the timeout has
            // expired.
            .earily_unblock = true,
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
        error = process_create(timeout_process, &timeout, &args, &timeout_pid);
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
}
