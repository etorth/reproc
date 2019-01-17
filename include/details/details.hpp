/*
 * =====================================================================================
 *
 *       Filename: details.hpp
 *        Created: 01/16/2019 23:23:58
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

namespace details
{
    xmproc::errcode process_create(xmproc::details::proc_args args)
    {
#if defined(_WIN32)
        xmproc::details::windows_impl::process_create(args);
#else
        xmproc::details::posix_impl::process_create(args);
#endif
    }
}
