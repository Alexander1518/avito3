package com.amr.project.converter.mappers;

import com.amr.project.converter.MapperInterface;
import com.amr.project.model.dto.CityDto;
import com.amr.project.model.entity.City;
import org.mapstruct.Builder;
import org.mapstruct.Mapper;

import java.util.List;

@Mapper(builder = @Builder(disableBuilder = true), componentModel = "spring", uses = {AddressMapper.class, CountryMapper.class})
public interface CityMapper extends MapperInterface<CityDto, City> {


}