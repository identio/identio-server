/*
 This file is part of Ident.io

 Ident.io - A flexible authentication server
 Copyright (C) Loeiz TANGUY

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as
 published by the Free Software Foundation, either version 3 of the
 License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package net.identio.server.model;

public class LdapPoolConfig {

	private int minIdleConnections = 4;
	private int maxIdleConnections = 8;
	private boolean testWhileIdle;
	private boolean testOnBorrow;
	private String testRequestFilter = "(objectclass=*)";
	private int timeBetweenEvictionRuns = 30;
	private int numTestsPerEvictionRun = 4;
	private int minEvictableIdleTime = -1;

	public int getMinIdleConnections() {
		return minIdleConnections;
	}

	public void setMinIdleConnections(int minIdleConnections) {
		this.minIdleConnections = minIdleConnections;
	}

	public int getMaxIdleConnections() {
		return maxIdleConnections;
	}

	public void setMaxIdleConnections(int maxIdleConnections) {
		this.maxIdleConnections = maxIdleConnections;
	}

	public boolean isTestWhileIdle() {
		return testWhileIdle;
	}

	public void setTestWhileIdle(boolean testWhileIdle) {
		this.testWhileIdle = testWhileIdle;
	}

	public boolean isTestOnBorrow() {
		return testOnBorrow;
	}

	public void setTestOnBorrow(boolean testOnBorrow) {
		this.testOnBorrow = testOnBorrow;
	}

	public String getTestRequestFilter() {
		return testRequestFilter;
	}

	public void setTestRequestFilter(String testRequestFilter) {
		this.testRequestFilter = testRequestFilter;
	}

	public int getTimeBetweenEvictionRuns() {
		return timeBetweenEvictionRuns;
	}

	public void setTimeBetweenEvictionRuns(int timeBetweenEvictionRuns) {
		this.timeBetweenEvictionRuns = timeBetweenEvictionRuns;
	}

	public int getNumTestsPerEvictionRun() {
		return numTestsPerEvictionRun;
	}

	public void setNumTestsPerEvictionRun(int numTestsPerEvictionRun) {
		this.numTestsPerEvictionRun = numTestsPerEvictionRun;
	}

	public int getMinEvictableIdleTime() {
		return minEvictableIdleTime;
	}

	public void setMinEvictableIdleTime(int minEvictableIdleTime) {
		this.minEvictableIdleTime = minEvictableIdleTime;
	}

}
