from setuptools import setup

setup(name='volatilitybot',
      version='3.0',
      description='Automated memory analysis framework',
      url='https://github.com/mkorman90/VolatilityBot',
      author='Martin Korman',
      author_email='martin@centauri.co.il',
      install_requires=['distorm3', 'pefile', 'yara-python', 'python-magic==0.4.12', 'elasticsearch==6.0.0', 'requests','pendulum', 'r2pipe'],
      zip_safe=False,
      entry_points={
            'console_scripts': ['volatilitybot_d=volatilitybot.daemon:main',
                                'gi_build_vbot=volatilitybot.utils.gi_builder:main',
                                'volatilitybot_post_processing_daemon=volatilitybot.post_processing.daemon:launch_daemon',
                                'volatilitybot_post_processing_workers=volatilitybot.post_processing.worker:start_workers_pool',
                                'volatilitybot_submit=volatilitybot.utils.submit:main'],
      }
      )
