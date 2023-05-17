import multiprocessing

worker_class = "uvicorn.workers.UvicornWorker"
workers = min(4, multiprocessing.cpu_count())
bind = "0.0.0.0:9082"
timeout = 90
keepalive = 3600
preload_app = True