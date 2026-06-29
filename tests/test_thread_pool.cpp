#include <gtest/gtest.h>
#include "thread_pool.h"
#include <atomic>
#include <chrono>
#include <set>
#include <mutex>
#include <thread>

TEST(ThreadPoolTest, AllTasksExecute) {
    std::atomic<int> counter{0};
    {
        ThreadPool pool(4);
        for (int i = 0; i < 100; ++i) {
            pool.enqueue([&counter]() { counter++; });
        }
        pool.wait_until_empty();
    }
    EXPECT_EQ(counter.load(), 100);
}

TEST(ThreadPoolTest, ConcurrentExecution) {
    std::set<std::thread::id> thread_ids;
    std::mutex mtx;
    {
        ThreadPool pool(4);
        for (int i = 0; i < 20; ++i) {
            pool.enqueue([&thread_ids, &mtx]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                std::lock_guard<std::mutex> lock(mtx);
                thread_ids.insert(std::this_thread::get_id());
            });
        }
        pool.wait_until_empty();
    }
    // With 4 threads and 20 tasks with sleeps, we should see multiple thread IDs
    EXPECT_GT(thread_ids.size(), 1u);
}

TEST(ThreadPoolTest, WaitBlocks) {
    std::atomic<bool> task_done{false};
    ThreadPool pool(2);
    pool.enqueue([&task_done]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        task_done = true;
    });
    pool.wait_until_empty();
    EXPECT_TRUE(task_done.load());
}

TEST(ThreadPoolTest, ClearQueue) {
    std::atomic<int> counter{0};
    {
        ThreadPool pool(1);
        // Submit a slow task to block the single thread
        pool.enqueue([&counter]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            counter++;
        });
        // Submit many fast tasks that should be pending
        for (int i = 0; i < 100; ++i) {
            pool.enqueue([&counter]() { counter++; });
        }
        // Clear pending tasks while the slow one is still running
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        pool.clear_queue();
        pool.wait_until_empty();
    }
    // Not all 101 tasks should have executed
    EXPECT_LT(counter.load(), 101);
    // At least the slow task should have run
    EXPECT_GE(counter.load(), 1);
}

TEST(ThreadPoolTest, SingleThread) {
    std::atomic<int> counter{0};
    {
        ThreadPool pool(1);
        for (int i = 0; i < 10; ++i) {
            pool.enqueue([&counter]() { counter++; });
        }
        pool.wait_until_empty();
    }
    EXPECT_EQ(counter.load(), 10);
}

TEST(ThreadPoolTest, DestructorJoins) {
    std::atomic<int> counter{0};
    {
        ThreadPool pool(2);
        for (int i = 0; i < 10; ++i) {
            pool.enqueue([&counter]() {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
                counter++;
            });
        }
        // Destructor should join all threads without crash
    }
    // All tasks should complete before destructor returns
    EXPECT_EQ(counter.load(), 10);
}

TEST(ThreadPoolTest, EmptyPool) {
    ThreadPool pool(4);
    // wait_until_empty on an empty pool should return immediately
    auto start = std::chrono::steady_clock::now();
    pool.wait_until_empty();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    EXPECT_LT(elapsed, 100);  // Should be nearly instant
}
