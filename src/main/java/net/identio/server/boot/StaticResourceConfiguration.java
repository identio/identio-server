/*
 This file is part of Ident.io.

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
package net.identio.server.boot;

import java.io.File;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import net.identio.server.service.configuration.ConfigurationService;

@Configuration
public class StaticResourceConfiguration extends WebMvcConfigurerAdapter {

	@Autowired
	private ConfigurationService configurationService;

	@Override
	public void addResourceHandlers(ResourceHandlerRegistry registry) {

		String resourceLocation = "file:"
				+ configurationService.getConfiguration().getGlobalConfiguration().getStaticResourcesPath();

		// Spring resource mapping is picky about the format of the path we
		// provide it.. The trailing file separator IS important...
		if (!resourceLocation.endsWith(File.separator)) {
			resourceLocation = new StringBuilder(resourceLocation).append(File.separator).toString();
		}

		registry.addResourceHandler("/**").addResourceLocations(resourceLocation);
	}

	@Override
	public void addViewControllers(ViewControllerRegistry registry) {
		registry.addViewController("/").setViewName("forward:/index.html");
	}
}