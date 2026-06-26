#ifndef PORTSCANNER_THREAD_POOL_H
#define PORTSCANNER_THREAD_POOL_H

#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <atomic>

class ThreadPool {
public:
    explicit ThreadPool(size_t num_threads);
    ~ThreadPool();

    // Enqueue a new task into the pool
    void enqueue(std::function<void()> task);

    // Block calling thread until all enqueued tasks are finished
    void wait_until_empty();

    // Purge all pending unstarted tasks from queue (for graceful cancellation)
    void clear_queue();

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;

    std::mutex queue_mutex;
    std::condition_variable cv_task;
    std::condition_variable cv_finished;

    std::atomic<size_t> active_tasks{0};
    bool stop = false;
};

#endif // PORTSCANNER_THREAD_POOL_H
