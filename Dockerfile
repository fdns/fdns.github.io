FROM ruby:2.7-buster

RUN gem install bundler:1.16.1

WORKDIR /app
ADD Gemfile /app/Gemfile
ADD Gemfile.lock /app/Gemfile.lock
RUN bundle

ADD . .

EXPOSE 4000
CMD ["bundle", "exec", "jekyll", "serve", "--host=0.0.0.0"]