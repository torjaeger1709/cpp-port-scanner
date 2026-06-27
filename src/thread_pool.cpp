#include "thread_pool.h"

ThreadPool::ThreadPool(size_t num_threads) {
    for (size_t i = 0; i < num_threads; ++i) {
        workers.emplace_back([this]() {
            while (true) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lock(this->queue_mutex);
                    this->cv_task.wait(lock, [this]() {
                        return this->stop || !this->tasks.empty();
                    });

                    if (this->stop && this->tasks.empty()) {
                        return;
                    }

                    task = std::move(this->tasks.front());
                    this->tasks.pop();
                    this->running_tasks++;
                }

                task();

                {
                    std::lock_guard<std::mutex> lock(this->queue_mutex);
                    running_tasks--;
                    if (tasks.empty() && running_tasks == 0) {
                        cv_finished.notify_all();
                    }
                }
            }
        });
    }
}

ThreadPool::~ThreadPool() {
    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        stop = true;
    }
    cv_task.notify_all();
    for (std::thread &worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
}

void ThreadPool::enqueue(std::function<void()> task) {
    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        tasks.push(std::move(task));
    }
    cv_task.notify_one();
}

void ThreadPool::wait_until_empty() {
    std::unique_lock<std::mutex> lock(queue_mutex);
    cv_finished.wait(lock, [this]() {
        return tasks.empty() && running_tasks == 0;
    });
}

void ThreadPool::clear_queue() {
    std::lock_guard<std::mutex> lock(queue_mutex);
    std::queue<std::function<void()>> empty;
    std::swap(tasks, empty);
    if (tasks.empty() && running_tasks == 0) {
        cv_finished.notify_all();
    }
}
