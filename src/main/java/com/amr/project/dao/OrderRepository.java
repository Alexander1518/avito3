package com.amr.project.dao;

import com.amr.project.model.entity.Category;
import com.amr.project.model.entity.Order;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.relational.core.mapping.Table;
import org.springframework.stereotype.Repository;

@Repository
public interface OrderRepository extends JpaRepository<Order, Long> {
}
