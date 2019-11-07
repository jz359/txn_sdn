import threading
import time

lock = threading.Lock()
cv = threading.Condition(lock)

flag = 0

class Runner(threading.Thread):
	def run(self):
		global flag, cv, lock
		# wait 10 seconds, then signal
		time.sleep(5)
		with lock:
			flag += 1
			print('updated')
			if flag == 2:
				print('time to notify main thread')
				cv.notifyAll()

t = Runner()
t2 = Runner()
t.start()
t2.start()
with lock:
	while flag < 2:
		print('waiting now')
		cv.wait()
		print('done waiting')
print('done with flag = ' + str(flag))
