#ifndef BENCH_H
#define BENCH_H
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>

// num_run: 运行总次数
// num_process：进程数
// run：测试的函数，其中接受参数pid，start，end分别为子进程标识pid，测试范围[start, end)
static int bench_multiprocesses(char *pre, int num_run, int num_processes, void (*run)(int, size_t, size_t)){

    // 计算每个线程需要完成的工作量
    size_t process_do_num = num_run / num_processes + 1;

    int status, i;
    pid_t pid[num_processes], retpid;

    struct timeval t0, t1;

    gettimeofday(&t0, NULL);

    for (i = 0; i < num_processes; i++)
    {
        if ((pid[i] = fork()) == 0)
        {
            // 计算每个子进程分配到的任务区间
            size_t start = i * process_do_num;
            size_t end = start + process_do_num;
            if(end > num_run) {
                end = num_run;
            }
            run(i, start, end);
        }
    }

    // 进程同步
    i = 0;
    while ((retpid = waitpid(pid[i++], &status, 0)) > 0)
    {
        if (WIFEXITED(status)){
            // 打印调试信息
            // printf("child %d terminated normally with exit status=%d\n", retpid, WEXITSTATUS(status));
        }else{
            printf("child %d terminated abnormally\n", retpid);
        }
    }
    gettimeofday(&t1, NULL);
    float total_time = t1.tv_sec - t0.tv_sec + 1E-6 * (t1.tv_usec - t0.tv_usec);
    printf("%s: %d processes do %d jobs in %.2f seconds, per second do %.2f times\n", pre, num_processes, num_run, total_time, num_run/total_time);
    return 0;
}

#endif